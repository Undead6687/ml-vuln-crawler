#!/usr/bin/env python3
"""
ml_handler.py - Production-Ready ML-Enhanced Vulnerability Analysis Engine

This module provides machine learning capabilities for vulnerability classification
and severity prediction using CVE data from MITRE and NVD sources.

Author: Senior Development Team
Version: 2.0.0
Python: 3.8+
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import json
import os
import re
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import warnings
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

# Configure logging for production FIRST
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress sklearn warnings for cleaner output
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')

# PyTorch imports for GPU acceleration (after logger is defined)
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    GPU_AVAILABLE = torch.cuda.is_available()
    if GPU_AVAILABLE:
        logger.info(f"🚀 GPU available: {torch.cuda.get_device_name(0)}")
    else:
        logger.info("⚠️ GPU not available, using CPU")
except ImportError:
    torch = None
    nn = None
    optim = None
    DataLoader = None
    TensorDataset = None
    GPU_AVAILABLE = False
    logger.info("⚠️ PyTorch not installed, GPU acceleration disabled")


@dataclass
class CVERecord:
    """Structured representation of a CVE record"""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    cwe_ids: List[str]
    year: int
    source: str
    processed_timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class ModelMetadata:
    """Model training metadata"""
    training_date: str
    training_samples: int
    test_samples: int
    test_accuracy: float
    cross_validation_scores: List[float]
    feature_columns: List[str]
    vectorizer_features: int
    model_type: str
    severity_mapping: Dict[int, str]
    cve_sources: List[str]
    training_duration_seconds: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class VulnerabilityClassifierNet(nn.Module):
    """PyTorch Neural Network for vulnerability classification"""
    
    def __init__(self, input_size: int, hidden_sizes: List[int] = [512, 256, 128, 64], 
                 num_classes: int = 4, dropout: float = 0.3):
        super(VulnerabilityClassifierNet, self).__init__()
        
        # Build network layers
        layers = []
        prev_size = input_size
        
        for hidden_size in hidden_sizes:
            layers.extend([
                nn.Linear(prev_size, hidden_size),
                nn.ReLU(),
                nn.BatchNorm1d(hidden_size),
                nn.Dropout(dropout)
            ])
            prev_size = hidden_size
        
        # Output layer
        layers.append(nn.Linear(prev_size, num_classes))
        
        self.network = nn.Sequential(*layers)
        
    def forward(self, x):
        return self.network(x)


class CVEDataProcessor:
    """Handles CVE data loading and processing from multiple sources"""
    
    def __init__(self, cve_base_path: Union[str, Path]):
        self.cve_base_path = Path(cve_base_path)
        self.supported_years = None
        self._discover_available_years()
        
    def _discover_available_years(self) -> None:
        """Auto-discover available CVE years in the directory structure"""
        try:
            if not self.cve_base_path.exists():
                logger.warning(f"CVE base path does not exist: {self.cve_base_path}")
                self.supported_years = []
                return
                
            year_dirs = [
                d for d in self.cve_base_path.iterdir() 
                if d.is_dir() and d.name.isdigit() and len(d.name) == 4
            ]
            
            self.supported_years = sorted([int(d.name) for d in year_dirs], reverse=True)
            logger.info(f"Discovered CVE years: {self.supported_years}")
            
        except Exception as e:
            logger.error(f"Error discovering CVE years: {e}")
            self.supported_years = []
    
    def get_available_years(self) -> List[int]:
        """Get list of available CVE years"""
        return self.supported_years.copy() if self.supported_years else []
    
    def load_cve_data(self, years: Optional[List[int]] = None) -> List[CVERecord]:
        """
        Load CVE data from available sources
        
        Args:
            years: List of years to process. If None, processes all available years.
            
        Returns:
            List of processed CVE records
        """
        if years is None:
            years = self.supported_years
        
        if not years:
            logger.warning("No CVE years available for processing")
            return []
        
        all_records = []
        
        for year in years:
            if year not in self.supported_years:
                logger.warning(f"Year {year} not available in CVE data")
                continue
                
            year_records = self._process_year_data(year)
            all_records.extend(year_records)
            logger.info(f"Processed {len(year_records)} records from {year}")
        
        logger.info(f"Total CVE records processed: {len(all_records)}")
        return all_records
    
    def _process_year_data(self, year: int) -> List[CVERecord]:
        """Process all CVE data for a specific year"""
        year_path = self.cve_base_path / str(year)
        records = []
        
        # Process NVD bulk file first (if available)
        nvd_file = year_path / f"nvdcve-1.1-{year}.json"
        if nvd_file.exists():
            try:
                nvd_records = self._process_nvd_file(nvd_file, year)
                records.extend(nvd_records)
                logger.info(f"Processed NVD bulk file for {year}: {len(nvd_records)} records")
            except Exception as e:
                logger.error(f"Error processing NVD file {nvd_file}: {e}")
        
        # Process individual MITRE CVE files
        individual_files = list(year_path.glob("CVE-*.json"))
        if individual_files:
            try:
                mitre_records = self._process_individual_cve_files(individual_files, year)
                records.extend(mitre_records)
                logger.info(f"Processed {len(individual_files)} individual CVE files for {year}")
            except Exception as e:
                logger.error(f"Error processing individual CVE files for {year}: {e}")
        
        return records
    
    def _process_nvd_file(self, nvd_file: Path, year: int) -> List[CVERecord]:
        """Process NVD bulk JSON file"""
        records = []
        
        try:
            with open(nvd_file, 'r', encoding='utf-8') as f:
                nvd_data = json.load(f)
            
            # Handle different NVD JSON formats
            vulnerabilities = nvd_data.get('CVE_Items', []) or nvd_data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                try:
                    record = self._parse_nvd_vulnerability(vuln, year, 'nvd')
                    if record:
                        records.append(record)
                except Exception as e:
                    logger.debug(f"Error parsing NVD vulnerability: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error reading NVD file {nvd_file}: {e}")
            raise
        
        return records
    
    def _process_individual_cve_files(self, cve_files: List[Path], year: int) -> List[CVERecord]:
        """Process individual MITRE CVE JSON files with multithreading"""
        records = []
        
        def process_single_file(file_path: Path) -> Optional[CVERecord]:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    cve_data = json.load(f)
                return self._parse_mitre_cve(cve_data, year, 'mitre')
            except Exception as e:
                logger.debug(f"Error processing {file_path}: {e}")
                return None
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_file = {
                executor.submit(process_single_file, file_path): file_path 
                for file_path in cve_files
            }
            
            for future in as_completed(future_to_file):
                try:
                    record = future.result()
                    if record:
                        records.append(record)
                except Exception as e:
                    file_path = future_to_file[future]
                    logger.debug(f"Error processing {file_path}: {e}")
        
        return records
    
    def _parse_nvd_vulnerability(self, vuln_data: Dict, year: int, source: str) -> Optional[CVERecord]:
        """Parse NVD vulnerability format"""
        try:
            # Extract CVE ID
            cve_id = vuln_data.get('cve', {}).get('CVE_data_meta', {}).get('ID', '') or \
                     vuln_data.get('cve', {}).get('id', '')
            
            if not cve_id:
                return None
            
            # Extract description
            descriptions = vuln_data.get('cve', {}).get('description', {}).get('description_data', []) or \
                         vuln_data.get('cve', {}).get('descriptions', [])
            
            description = ""
            for desc in descriptions:
                if desc.get('lang', '') == 'en' or not description:
                    description = desc.get('value', '')
                    break
            
            if not description:
                return None
            
            # Extract CVSS score and severity
            cvss_score, severity = self._extract_cvss_info(vuln_data)
            
            # Extract CWE information
            cwe_ids = self._extract_cwe_ids(vuln_data)
            
            return CVERecord(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                cwe_ids=cwe_ids,
                year=year,
                source=source,
                processed_timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except Exception as e:
            logger.debug(f"Error parsing NVD vulnerability: {e}")
            return None
    
    def _parse_mitre_cve(self, cve_data: Dict, year: int, source: str) -> Optional[CVERecord]:
        """Parse MITRE CVE format"""
        try:
            # Extract CVE ID
            cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')
            
            if not cve_id:
                return None
            
            # Extract description
            description_data = cve_data.get('description', {}).get('description_data', [])
            description = ""
            
            for desc in description_data:
                if desc.get('lang', '') == 'en' or not description:
                    description = desc.get('value', '')
                    break
            
            if not description or description.lower().strip() == '** reserved **':
                return None
            
            # For MITRE data, we don't have CVSS scores, so we'll use medium severity
            # and estimate a score based on description analysis
            cvss_score = self._estimate_cvss_from_description(description)
            severity = self._cvss_to_severity(cvss_score)
            
            # Extract CWE information
            cwe_ids = self._extract_cwe_ids_mitre(cve_data)
            
            return CVERecord(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                cwe_ids=cwe_ids,
                year=year,
                source=source,
                processed_timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except Exception as e:
            logger.debug(f"Error parsing MITRE CVE: {e}")
            return None
    
    def _extract_cvss_info(self, vuln_data: Dict) -> Tuple[float, str]:
        """Extract CVSS score and severity from NVD data"""
        cvss_score = 0.0
        severity = "unknown"
        
        try:
            # Try CVSS v3 first
            cvss_v3 = vuln_data.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}) or \
                     vuln_data.get('metrics', {}).get('cvssMetricV3', [{}])
            
            if isinstance(cvss_v3, list) and cvss_v3:
                cvss_v3 = cvss_v3[0].get('cvssData', {})
            
            if cvss_v3.get('baseScore'):
                cvss_score = float(cvss_v3['baseScore'])
                severity = cvss_v3.get('baseSeverity', '').lower()
            else:
                # Fallback to CVSS v2
                cvss_v2 = vuln_data.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {})
                if cvss_v2.get('baseScore'):
                    cvss_score = float(cvss_v2['baseScore'])
                    severity = self._cvss_v2_to_severity(cvss_score)
        
        except (ValueError, TypeError) as e:
            logger.debug(f"Error extracting CVSS info: {e}")
        
        return cvss_score, severity
    
    def _extract_cwe_ids(self, vuln_data: Dict) -> List[str]:
        """Extract CWE IDs from NVD vulnerability data"""
        cwe_ids = []
        
        try:
            problems = vuln_data.get('cve', {}).get('problemtype', {}).get('problemtype_data', []) or \
                      vuln_data.get('cve', {}).get('weaknesses', [])
            
            for problem in problems:
                descriptions = problem.get('description', [])
                for desc in descriptions:
                    value = desc.get('value', '')
                    if value and value.startswith('CWE-'):
                        cwe_ids.append(value)
        except Exception as e:
            logger.debug(f"Error extracting CWE IDs: {e}")
        
        return list(set(cwe_ids))  # Remove duplicates
    
    def _extract_cwe_ids_mitre(self, cve_data: Dict) -> List[str]:
        """Extract CWE IDs from MITRE CVE data"""
        cwe_ids = []
        
        try:
            problem_type = cve_data.get('problemtype', {}).get('problemtype_data', [])
            for problem in problem_type:
                descriptions = problem.get('description', [])
                for desc in descriptions:
                    value = desc.get('value', '')
                    if value and value.startswith('CWE-'):
                        cwe_ids.append(value)
        except Exception as e:
            logger.debug(f"Error extracting MITRE CWE IDs: {e}")
        
        return list(set(cwe_ids))  # Remove duplicates
    
    def _estimate_cvss_from_description(self, description: str) -> float:
        """Estimate CVSS score from vulnerability description for MITRE data"""
        desc_lower = description.lower()
        
        # High severity indicators
        if any(keyword in desc_lower for keyword in [
            'remote code execution', 'rce', 'arbitrary code execution',
            'privilege escalation', 'root access', 'system compromise'
        ]):
            return 8.5
        
        # Medium-high severity
        elif any(keyword in desc_lower for keyword in [
            'sql injection', 'command injection', 'path traversal',
            'cross-site scripting', 'xss', 'csrf', 'authentication bypass'
        ]):
            return 7.0
        
        # Medium severity
        elif any(keyword in desc_lower for keyword in [
            'information disclosure', 'denial of service', 'dos',
            'memory corruption', 'buffer overflow'
        ]):
            return 5.5
        
        # Low severity
        elif any(keyword in desc_lower for keyword in [
            'information leak', 'version disclosure', 'directory traversal'
        ]):
            return 3.0
        
        # Default medium
        return 5.0
    
    def _cvss_v2_to_severity(self, score: float) -> str:
        """Convert CVSS v2 score to severity level"""
        if score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0.0:
            return "low"
        else:
            return "info"


class MLVulnerabilityHandler:
    """
    Production-ready ML handler for vulnerability analysis and prediction
    
    This class provides comprehensive machine learning capabilities for:
    - CVE data processing and feature extraction
    - Vulnerability severity classification
    - Pattern recognition and prediction
    - Model training, evaluation, and persistence
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize ML handler with configuration"""
        self.config_file = config_path
        self.config = self._load_config(config_path)
        self.model = None
        self.vectorizer = None
        self.label_encoder = None
        self.feature_columns = []
        
        # Paths configuration
        self.cve_data_path = Path(self.config.get('cve_data', {}).get('data_path', './cves/'))
        self.processed_path = Path(self.config.get('cve_data', {}).get('processed_path', './cves/processed/'))
        self.models_path = Path('./trained_models/')
        
        # Initialize components
        self.cve_processor = CVEDataProcessor(self.cve_data_path)
        self.training_data = None
        self.model_metadata = None
        
        # Thread safety
        self._model_lock = threading.RLock()
        
        # Create directories
        self._ensure_directories()
        
        logger.info(f"MLVulnerabilityHandler initialized with CVE path: {self.cve_data_path}")
        logger.info(f"Available CVE years: {self.cve_processor.get_available_years()}")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration with fallback defaults"""
        default_config = {
            'cve_data': {
                'data_path': './cves/',
                'processed_path': './cves/processed/',
                'years_to_process': [1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025]
            },
            'ml_training': {
                'model_type': 'random_forest',
                'test_size': 0.2,
                'validation_split': 0.2,
                'feature_extraction': {
                    'max_features': 5000,
                    'ngram_range': [1, 2],
                    'min_df': 2,
                    'max_df': 0.95
                },
                'model_params': {
                    'n_estimators': 100,
                    'max_depth': 10,
                    'random_state': 42
                }
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f) or {}
                
                # Deep merge configuration
                for section in default_config:
                    if section in user_config:
                        if isinstance(default_config[section], dict):
                            default_config[section].update(user_config[section])
                        else:
                            default_config[section] = user_config[section]
                
                logger.info(f"Configuration loaded from {config_path}")
            else:
                logger.warning(f"Config file {config_path} not found, using defaults")
                
        except Exception as e:
            logger.error(f"Error loading config: {e}, using defaults")
        
        return default_config
    
    def _ensure_directories(self) -> None:
        """Ensure required directories exist"""
        for path in [self.processed_path, self.models_path]:
            try:
                path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.error(f"Error creating directory {path}: {e}")
    
    @contextmanager
    def _model_context(self):
        """Context manager for thread-safe model operations"""
        with self._model_lock:
            yield
    
    def collect_and_process_cve_data(self, years: Optional[List[int]] = None) -> bool:
        """
        Collect and process CVE data from available sources
        
        Args:
            years: List of years to process. If None, uses config or auto-detected years.
            
        Returns:
            True if successful, False otherwise
        """
        start_time = time.time()
        
        try:
            if years is None:
                years = self.config.get('cve_data', {}).get('years_to_process', 
                                                           self.cve_processor.get_available_years())
            
            # Filter to only available years
            available_years = self.cve_processor.get_available_years()
            years = [year for year in years if year in available_years]
            
            if not years:
                logger.error("No valid CVE years available for processing")
                return False
            
            logger.info(f"Processing CVE data for years: {years}")
            
            # Load CVE data
            cve_records = self.cve_processor.load_cve_data(years)
            
            if not cve_records:
                logger.error("No CVE records loaded")
                return False
            
            # Convert to training format
            training_data = []
            for record in cve_records:
                if record.description and record.cvss_score > 0:
                    training_data.append(record.to_dict())
            
            if not training_data:
                logger.error("No valid training data after processing")
                return False
            
            # Save processed data
            processed_file = self.processed_path / "training_dataset.json"
            with open(processed_file, 'w', encoding='utf-8') as f:
                json.dump(training_data, f, indent=2, ensure_ascii=False)
            
            processing_time = time.time() - start_time
            logger.info(f"Successfully processed {len(training_data)} CVE records in {processing_time:.2f}s")
            logger.info(f"Processed data saved to: {processed_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error collecting CVE data: {e}")
            return False
    
    def prepare_training_data(self) -> bool:
        """Prepare training data from processed CVEs"""
        try:
            processed_file = self.processed_path / "training_dataset.json"
            
            if not processed_file.exists():
                logger.error(f"Training data not found at {processed_file}")
                logger.info("Run collect_and_process_cve_data() first")
                return False
            
            with open(processed_file, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
            
            if not raw_data:
                logger.error("No training data available")
                return False
            
            # Convert to DataFrame for processing
            df = pd.DataFrame(raw_data)
            logger.info(f"Loaded {len(df)} CVE records for training")
            
            # Feature engineering
            df = self._engineer_features(df)
            
            # Clean and validate data
            df = self._clean_training_data(df)
            
            if len(df) == 0:
                logger.error("No valid training data after cleaning")
                return False
            
            logger.info(f"Prepared {len(df)} training samples")
            logger.info(f"Severity distribution: {df['severity'].value_counts().to_dict()}")
            
            self.training_data = df
            return True
            
        except Exception as e:
            logger.error(f"Error preparing training data: {e}")
            return False
    
    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer features from CVE data"""
        logger.info("Engineering features from CVE descriptions...")
        
        try:
            # Text-based features
            df['description_length'] = df['description'].str.len()
            df['word_count'] = df['description'].str.split().str.len()
            
            # Security-specific features
            df['has_remote'] = df['description'].str.contains(
                r'remote|remotely', case=False, regex=True, na=False
            ).astype(int)
            
            df['has_injection'] = df['description'].str.contains(
                r'injection|inject', case=False, regex=True, na=False
            ).astype(int)
            
            df['has_xss'] = df['description'].str.contains(
                r'cross.site|xss|scripting', case=False, regex=True, na=False
            ).astype(int)
            
            df['has_auth'] = df['description'].str.contains(
                r'authentication|authorization|auth', case=False, regex=True, na=False
            ).astype(int)
            
            df['has_overflow'] = df['description'].str.contains(
                r'overflow|buffer|heap|stack', case=False, regex=True, na=False
            ).astype(int)
            
            df['has_traversal'] = df['description'].str.contains(
                r'traversal|directory|path', case=False, regex=True, na=False
            ).astype(int)
            
            df['has_execution'] = df['description'].str.contains(
                r'execution|execute|rce', case=False, regex=True, na=False
            ).astype(int)
            
            df['has_privilege'] = df['description'].str.contains(
                r'privilege|escalation|root|admin', case=False, regex=True, na=False
            ).astype(int)
            
            # CWE features
            df['cwe_count'] = df['cwe_ids'].apply(len)
            df['has_cwe'] = (df['cwe_count'] > 0).astype(int)
            
            # Source features
            df['is_nvd'] = (df['source'] == 'nvd').astype(int)
            df['is_mitre'] = (df['source'] == 'mitre').astype(int)
            
            # Year features (could help with temporal patterns)
            df['year_2023'] = (df['year'] == 2023).astype(int)
            df['year_2024'] = (df['year'] == 2024).astype(int)
            
            logger.info("Feature engineering completed successfully")
            return df
            
        except Exception as e:
            logger.error(f"Error in feature engineering: {e}")
            raise
    
    def _clean_training_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and validate training data"""
        logger.info("Cleaning training data...")
        
        original_count = len(df)
        
        # Remove records with invalid descriptions
        df = df[df['description'].str.len() >= 20]  # Minimum description length
        df = df[~df['description'].str.contains(r'^\*\* reserved \*\*', case=False, regex=True, na=False)]
        
        # Remove records with invalid CVSS scores
        df = df[(df['cvss_score'] > 0) & (df['cvss_score'] <= 10)]
        
        # Map severity to numeric values
        severity_map = {
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3,
            'info': 0  # Map info to low
        }
        
        df['severity_numeric'] = df['severity'].map(severity_map)
        df = df[df['severity_numeric'].notna()]
        
        # Remove outliers in description length (optional)
        desc_length_95th = df['description_length'].quantile(0.95)
        df = df[df['description_length'] <= desc_length_95th]
        
        cleaned_count = len(df)
        removed_count = original_count - cleaned_count
        
        logger.info(f"Removed {removed_count} invalid records, {cleaned_count} remaining")
        
        return df
    
    def train_vulnerability_classifier(self) -> bool:
        """Train the ML model for vulnerability classification"""
        if self.training_data is None:
            if not self.prepare_training_data():
                return False
        
        start_time = time.time()
        
        try:
            with self._model_context():
                df = self.training_data
                logger.info(f"Training vulnerability classifier on {len(df)} samples...")
                
                # Prepare features
                feature_columns = [
                    'description_length', 'word_count', 'has_remote', 'has_injection', 
                    'has_xss', 'has_auth', 'has_overflow', 'has_traversal',
                    'has_execution', 'has_privilege', 'cwe_count', 'has_cwe',
                    'is_nvd', 'is_mitre', 'year_2023', 'year_2024', 'cvss_score'
                ]
                
                # Text vectorization
                logger.info("Vectorizing vulnerability descriptions...")
                self.vectorizer = TfidfVectorizer(
                    max_features=self.config['ml_training']['feature_extraction']['max_features'],
                    ngram_range=tuple(self.config['ml_training']['feature_extraction']['ngram_range']),
                    min_df=self.config['ml_training']['feature_extraction']['min_df'],
                    max_df=self.config['ml_training']['feature_extraction']['max_df'],
                    stop_words='english',
                    lowercase=True,
                    strip_accents='unicode'
                )
                
                description_features = self.vectorizer.fit_transform(df['description']).toarray()
                
                # Combine all features
                numerical_features = df[feature_columns].values
                X = np.hstack([numerical_features, description_features])
                y = df['severity_numeric'].values
                
                # Split data
                test_size = self.config['ml_training']['test_size']
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=test_size, random_state=42, stratify=y
                )
                
                # Train model
                logger.info("Training Random Forest classifier...")
                model_params = self.config['ml_training']['model_params']
                self.model = RandomForestClassifier(
                    n_estimators=model_params['n_estimators'],
                    max_depth=model_params['max_depth'],
                    random_state=model_params['random_state'],
                    n_jobs=-1,
                    class_weight='balanced'  # Handle class imbalance
                )
                
                self.model.fit(X_train, y_train)
                
                # Evaluate model
                y_pred = self.model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                
                # Cross-validation
                cv_scores = cross_val_score(self.model, X_train, y_train, cv=5, scoring='accuracy')
                
                # Store feature columns and metadata
                self.feature_columns = feature_columns
                
                training_time = time.time() - start_time
                
                self.model_metadata = ModelMetadata(
                    training_date=datetime.now(timezone.utc).isoformat(),
                    training_samples=len(X_train),
                    test_samples=len(X_test),
                    test_accuracy=accuracy,
                    cross_validation_scores=cv_scores.tolist(),
                    feature_columns=feature_columns,
                    vectorizer_features=description_features.shape[1],
                    model_type='RandomForestClassifier',
                    severity_mapping={0: 'low', 1: 'medium', 2: 'high', 3: 'critical'},
                    cve_sources=list(df['source'].unique()),
                    training_duration_seconds=training_time
                )
                
                logger.info(f"Model training completed successfully!")
                logger.info(f"Training time: {training_time:.2f}s")
                logger.info(f"Training samples: {len(X_train)}")
                logger.info(f"Test samples: {len(X_test)}")
                logger.info(f"Test accuracy: {accuracy:.3f}")
                logger.info(f"Cross-validation mean: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
                
                return True
                
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return False

    def train_gpu_accelerated_classifier(self, df=None, dataset_size_limit=None) -> bool:
        """Train using GPU-only neural network (no hybrid model)"""
        if torch is None or not GPU_AVAILABLE:
            logger.warning("🚫 GPU not available, cannot use GPU training")
            return False

        if df is None:
            if self.training_data is None:
                if not self.prepare_training_data():
                    return False
            df = self.training_data
        
        start_time = time.time()
        
        try:
            with self._model_context():
                logger.info(f"🚀 Starting GPU-accelerated training on {len(df)} samples...")
                
                # Apply dataset size limit if specified
                if dataset_size_limit and len(df) > dataset_size_limit:
                    df = df.sample(n=dataset_size_limit, random_state=42)
                    logger.info(f"📊 Limited dataset to {len(df)} samples for GPU training")
                
                # Prepare features (same as CPU version)
                feature_columns = [
                    'description_length', 'word_count', 'has_remote', 'has_injection', 
                    'has_xss', 'has_auth', 'has_overflow', 'has_traversal',
                    'has_execution', 'has_privilege', 'cwe_count', 'has_cwe',
                    'is_nvd', 'is_mitre', 'year_2023', 'year_2024', 'cvss_score'
                ]
                
                # Text vectorization
                logger.info("🔤 Vectorizing vulnerability descriptions...")
                self.vectorizer = TfidfVectorizer(
                    max_features=self.config['ml_training']['feature_extraction']['max_features'],
                    ngram_range=tuple(self.config['ml_training']['feature_extraction']['ngram_range']),
                    min_df=self.config['ml_training']['feature_extraction']['min_df'],
                    max_df=self.config['ml_training']['feature_extraction']['max_df'],
                    stop_words='english',
                    lowercase=True,
                    strip_accents='unicode'
                )
                
                description_features = self.vectorizer.fit_transform(df['description']).toarray()
                
                # Combine all features
                numerical_features = df[feature_columns].values
                X = np.hstack([numerical_features, description_features]).astype(np.float32)
                y = df['severity_numeric'].values.astype(np.int64)
                
                # Split data
                test_size = self.config['ml_training']['test_size']
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=test_size, random_state=42, stratify=y
                )
                
                # Convert to PyTorch tensors
                device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
                logger.info(f"🎯 Using device: {device}")
                
                X_train_tensor = torch.from_numpy(X_train).to(device)
                X_test_tensor = torch.from_numpy(X_test).to(device)
                y_train_tensor = torch.from_numpy(y_train).to(device)
                y_test_tensor = torch.from_numpy(y_test).to(device)
                
                # Create neural network
                input_size = X_train.shape[1]
                gpu_model = VulnerabilityClassifierNet(
                    input_size=input_size,
                    hidden_sizes=[512, 256, 128, 64],
                    num_classes=4,
                    dropout=0.3
                ).to(device)
                
                logger.info(f"🧠 Neural network created with input size: {input_size}")
                
                # Train neural network
                success = self._train_neural_network_gpu(gpu_model, X_train_tensor, y_train_tensor, X_test_tensor, y_test_tensor, device)
                
                if success:
                    # 🔥 PURE GPU MODEL - No hybrid complexity
                    logger.info("🎯 Creating pure GPU model (no hybrid)...")
                    
                    # Store the GPU model directly with CPU tensors for pickle compatibility
                    gpu_model.cpu()  # Move to CPU for saving
                    self.model = gpu_model
                    self.device = device  # Store device info
                    
                    # Store training metadata
                    training_time = time.time() - start_time
                    gpu_model.eval()
                    with torch.no_grad():
                        test_outputs = gpu_model(X_test_tensor.cpu())
                        _, predicted = torch.max(test_outputs, 1)
                        gpu_accuracy = (predicted == y_test_tensor.cpu()).float().mean().item()

                    self.model_metadata = ModelMetadata(
                        training_date=datetime.now(timezone.utc).isoformat(),
                        training_samples=len(X_train),
                        test_samples=len(X_test),
                        test_accuracy=gpu_accuracy,
                        cross_validation_scores=[gpu_accuracy],  # Simplified for GPU
                        feature_columns=feature_columns,
                        vectorizer_features=description_features.shape[1],
                        model_type='PureGPU-NeuralNetwork',  # Changed from hybrid
                        severity_mapping={0: 'low', 1: 'medium', 2: 'high', 3: 'critical'},
                        cve_sources=list(df['source'].unique()),
                        training_duration_seconds=training_time
                    )
                    
                    logger.info("✅ Pure GPU model created successfully!")
                    logger.info(f"🕐 Training time: {training_time:.2f}s")
                    logger.info(f"📊 GPU accuracy: {gpu_accuracy:.3f}")
                    return True
                else:
                    logger.error("❌ GPU neural network training failed")
                    return False
                
        except Exception as e:
            logger.error(f"❌ Error in GPU training: {e}")
            return False

    def _train_neural_network_gpu(self, model, X_train, y_train, X_test, y_test, device) -> bool:
        """Train the neural network on GPU"""
        try:
            # Training parameters
            learning_rate = 0.001
            batch_size = 128
            epochs = 50
            
            # Loss and optimizer
            criterion = nn.CrossEntropyLoss()
            optimizer = optim.Adam(model.parameters(), lr=learning_rate, weight_decay=1e-4)
            scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, 'min', patience=5)
            
            # Create data loader
            train_dataset = TensorDataset(X_train, y_train)
            train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
            
            logger.info(f"🏋️ Training neural network: {epochs} epochs, batch size {batch_size}")
            
            model.train()
            best_loss = float('inf')
            patience_counter = 0
            max_patience = 10
            
            for epoch in range(epochs):
                epoch_loss = 0.0
                num_batches = 0
                
                for batch_X, batch_y in train_loader:
                    optimizer.zero_grad()
                    outputs = model(batch_X)
                    loss = criterion(outputs, batch_y)
                    loss.backward()
                    optimizer.step()
                    
                    epoch_loss += loss.item()
                    num_batches += 1
                
                avg_loss = epoch_loss / num_batches
                scheduler.step(avg_loss)
                
                # Early stopping
                if avg_loss < best_loss:
                    best_loss = avg_loss
                    patience_counter = 0
                else:
                    patience_counter += 1
                
                if (epoch + 1) % 10 == 0:
                    logger.info(f"🔄 Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")
                
                if patience_counter >= max_patience:
                    logger.info(f"🛑 Early stopping at epoch {epoch+1}")
                    break
            
            logger.info("✅ Neural network training completed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Neural network training error: {e}")
            return False
    
    def save_trained_model(self) -> bool:
        """Save pure GPU model (PyTorch native) or CPU model"""
        if self.model is None or self.vectorizer is None:
            logger.error("No trained model to save")
            return False
        
        try:
            with self._model_context():
                # Check if this is a GPU PyTorch model
                if hasattr(self.model, 'network') and torch is not None:
                    # Save PyTorch model
                    model_path = self.models_path / "gpu_vulnerability_model.pth"
                    torch.save({
                        'model_state_dict': self.model.state_dict(),
                        'model_config': {
                            'input_size': self.model.network[0].in_features,
                            'hidden_sizes': [512, 256, 128, 64],
                            'num_classes': 4,
                            'dropout': 0.3
                        }
                    }, model_path)
                    
                    logger.info(f"✅ GPU model saved to {model_path}")
                else:
                    # Save traditional scikit-learn model
                    model_path = self.models_path / "vulnerability_classifier.pkl"
                    joblib.dump(self.model, model_path)
                    logger.info(f"✅ CPU model saved to {model_path}")
                
                # Save vectorizer (no issues with this)
                vectorizer_path = self.models_path / "feature_vectorizer.pkl" 
                joblib.dump(self.vectorizer, vectorizer_path)
                
                # Save metadata
                metadata_path = self.models_path / "model_metadata.json"
                with open(metadata_path, 'w', encoding='utf-8') as f:
                    json.dump(self.model_metadata.to_dict(), f, indent=2, ensure_ascii=False)
                
                # Save feature columns
                features_path = self.models_path / "feature_columns.json"
                with open(features_path, 'w') as f:
                    json.dump(self.feature_columns, f, indent=2)
                
                logger.info(f"✅ Vectorizer saved to {vectorizer_path}")
                logger.info(f"✅ Metadata saved to {metadata_path}")
                logger.info("✅ Pure GPU model saved successfully!")
                
                return True
                
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def load_trained_model(self) -> bool:
        """Load pure GPU model or CPU model"""
        try:
            with self._model_context():
                # Try to load GPU model first
                gpu_model_path = self.models_path / "gpu_vulnerability_model.pth"
                cpu_model_path = self.models_path / "vulnerability_classifier.pkl"
                vectorizer_path = self.models_path / "feature_vectorizer.pkl"
                metadata_path = self.models_path / "model_metadata.json"
                features_path = self.models_path / "feature_columns.json"
                
                # Load common components
                if not vectorizer_path.exists() or not metadata_path.exists():
                    logger.warning("Missing vectorizer or metadata files")
                    return False
                
                self.vectorizer = joblib.load(vectorizer_path)
                
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    metadata_dict = json.load(f)
                    self.model_metadata = ModelMetadata(**metadata_dict)
                
                # Load feature columns
                if features_path.exists():
                    with open(features_path, 'r') as f:
                        self.feature_columns = json.load(f)
                
                # Try GPU model first
                if gpu_model_path.exists() and torch is not None:
                    try:
                        checkpoint = torch.load(gpu_model_path, map_location='cpu')
                        model_config = checkpoint['model_config']
                        
                        # Recreate model architecture
                        self.model = VulnerabilityClassifierNet(
                            input_size=model_config['input_size'],
                            hidden_sizes=model_config['hidden_sizes'],
                            num_classes=model_config['num_classes'],
                            dropout=model_config['dropout']
                        )
                        
                        # Load weights
                        self.model.load_state_dict(checkpoint['model_state_dict'])
                        
                        logger.info("✅ Pure GPU model loaded successfully!")
                        return True
                        
                    except Exception as e:
                        logger.error(f"Failed to load GPU model: {e}")
                        # Fall back to CPU model
                
                # Try CPU model
                if cpu_model_path.exists():
                    self.model = joblib.load(cpu_model_path)
                    logger.info("✅ CPU model loaded successfully!")
                    return True
                
                logger.error("No valid model found")
                return False
                
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False

    def predict_vulnerability_gpu(self, description: str) -> Dict[str, Any]:
        """GPU-only vulnerability prediction"""
        if self.model is None:
            return {'error': 'No model loaded'}
        
        try:
            # Check if this is a GPU model
            if not hasattr(self.model, 'network'):
                # Fall back to CPU prediction for non-GPU models
                return self.predict_vulnerability_cpu(description)
            
            # Move model to GPU for prediction
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            self.model.to(device)
            self.model.eval()
            
            # Prepare features (same as existing)
            features = self._extract_vulnerability_features(description)
            description_vector = self.vectorizer.transform([description]).toarray()
            
            # Combine features using the feature values directly
            numerical_features = np.array([[
                features['description_length'], features['word_count'],
                features['has_remote'], features['has_injection'],
                features['has_xss'], features['has_auth'],
                features['has_overflow'], features['has_traversal'],
                features['has_execution'], features['has_privilege'],
                features['cwe_count'], features['has_cwe'],
                features['is_nvd'], features['is_mitre'],
                features['year_2023'], features['year_2024'],
                features['cvss_score']
            ]])
            
            X = np.hstack([numerical_features, description_vector]).astype(np.float32)
            X_tensor = torch.from_numpy(X).to(device)
            
            # GPU prediction
            with torch.no_grad():
                outputs = self.model(X_tensor)
                probabilities = torch.softmax(outputs, dim=1).cpu().numpy()
                predicted = torch.argmax(outputs, dim=1).cpu().numpy()
            
            severity_mapping = {0: 'low', 1: 'medium', 2: 'high', 3: 'critical'}
            
            return {
                'predicted_severity': severity_mapping[predicted[0]],
                'confidence': float(probabilities[0][predicted[0]]),
                'probabilities': {
                    'low': float(probabilities[0][0]),
                    'medium': float(probabilities[0][1]),
                    'high': float(probabilities[0][2]),
                    'critical': float(probabilities[0][3])
                },
                'model_type': 'gpu_neural_network'
            }
            
        except Exception as e:
            logger.error(f"GPU prediction error: {e}")
            return {'error': str(e)}

    def predict_vulnerability_cpu(self, description: str) -> Dict[str, Any]:
        """CPU fallback vulnerability prediction"""
        if self.model is None:
            return {'error': 'No model loaded'}
        
        try:
            # Extract features
            features = self._extract_vulnerability_features(description)
            description_vector = self.vectorizer.transform([description]).toarray()
            
            # Combine features using the feature values directly
            numerical_features = np.array([[
                features['description_length'], features['word_count'],
                features['has_remote'], features['has_injection'],
                features['has_xss'], features['has_auth'],
                features['has_overflow'], features['has_traversal'],
                features['has_execution'], features['has_privilege'],
                features['cwe_count'], features['has_cwe'],
                features['is_nvd'], features['is_mitre'],
                features['year_2023'], features['year_2024'],
                features['cvss_score']
            ]])
            
            X = np.hstack([numerical_features, description_vector])
            
            # CPU prediction
            probabilities = self.model.predict_proba(X)[0]
            predicted = self.model.predict(X)[0]
            
            severity_mapping = {0: 'low', 1: 'medium', 2: 'high', 3: 'critical'}
            
            return {
                'predicted_severity': severity_mapping[predicted],
                'confidence': float(probabilities[predicted]),
                'probabilities': {
                    'low': float(probabilities[0]),
                    'medium': float(probabilities[1]),
                    'high': float(probabilities[2]),
                    'critical': float(probabilities[3])
                },
                'model_type': 'cpu_random_forest'
            }
            
        except Exception as e:
            logger.error(f"CPU prediction error: {e}")
            return {'error': str(e)}
    
    def enhance_vulnerability_analysis(self, scan_report: Dict) -> Dict:
        """
        Enhance scan results with ML predictions - MAIN INTEGRATION POINT
        
        Args:
            scan_report: Original scan report from scanner.py
            
        Returns:
            Enhanced scan report with ML predictions
        """
        if self.model is None:
            if not self.load_trained_model():
                logger.warning("No trained model available, skipping ML analysis")
                return scan_report
        
        logger.info("Enhancing vulnerability analysis with ML predictions...")
        
        try:
            enhanced_report = scan_report.copy()
            vulnerabilities = scan_report.get('vulnerabilities', [])
            
            if not vulnerabilities:
                logger.info("No vulnerabilities to enhance")
                return enhanced_report
            
            # Batch process vulnerabilities for better performance
            enhanced_vulnerabilities = self._batch_predict_vulnerabilities(vulnerabilities)
            
            enhanced_report['vulnerabilities'] = enhanced_vulnerabilities
            enhanced_report['ml_summary'] = self._generate_ml_summary(enhanced_vulnerabilities)
            
            logger.info(f"Enhanced {len(enhanced_vulnerabilities)} vulnerability records")
            
            return enhanced_report
            
        except Exception as e:
            logger.error(f"Error enhancing vulnerability analysis: {e}")
            return scan_report
    
    def _batch_predict_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Predict vulnerabilities in batch using GPU/CPU prediction methods"""
        try:
            enhanced_vulns = vulnerabilities.copy()
            
            # Process each vulnerability individually using our new prediction methods
            for i, vuln in enumerate(enhanced_vulns):
                description = vuln.get('description', '')
                if description and len(description.strip()) >= 10:
                    # Use GPU prediction if available, fall back to CPU
                    if hasattr(self.model, 'network') and torch is not None:
                        prediction_result = self.predict_vulnerability_gpu(description)
                    else:
                        prediction_result = self.predict_vulnerability_cpu(description)
                    
                    if 'error' not in prediction_result:
                        ml_analysis = {
                            'predicted_severity': prediction_result['predicted_severity'],
                            'confidence': prediction_result['confidence'],
                            'model_used': True,
                            'model_type': prediction_result['model_type'],
                            'prediction_probabilities': prediction_result['probabilities']
                        }
                        
                        enhanced_vulns[i]['ml_analysis'] = ml_analysis
                        
                        # Enhanced severity if confidence is high
                        if ml_analysis['confidence'] > 0.7:
                            enhanced_vulns[i]['ml_enhanced_severity'] = ml_analysis['predicted_severity']
                            enhanced_vulns[i]['original_severity'] = vuln.get('severity', 'medium')
                    else:
                        logger.warning(f"Prediction failed for vulnerability {i}: {prediction_result['error']}")
            
            return enhanced_vulns
            
        except Exception as e:
            logger.error(f"Error in batch vulnerability prediction: {e}")
            return vulnerabilities
    
    def _extract_vulnerability_features(self, description: str) -> Dict[str, Union[int, float]]:
        """Extract features from vulnerability description"""
        desc_lower = description.lower()
        
        return {
            'description_length': len(description),
            'word_count': len(description.split()),
            'has_remote': int(any(term in desc_lower for term in ['remote', 'remotely'])),
            'has_injection': int(any(term in desc_lower for term in ['injection', 'inject'])),
            'has_xss': int(any(term in desc_lower for term in ['cross-site', 'xss', 'scripting'])),
            'has_auth': int(any(term in desc_lower for term in ['authentication', 'authorization', 'auth'])),
            'has_overflow': int(any(term in desc_lower for term in ['overflow', 'buffer', 'heap', 'stack'])),
            'has_traversal': int(any(term in desc_lower for term in ['traversal', 'directory', 'path'])),
            'has_execution': int(any(term in desc_lower for term in ['execution', 'execute', 'rce'])),
            'has_privilege': int(any(term in desc_lower for term in ['privilege', 'escalation', 'root', 'admin'])),
            'cwe_count': len(re.findall(r'CWE-\d+', description)),
            'has_cwe': int('cwe-' in desc_lower),
            # Additional features expected by trained model
            'is_nvd': 0,  # Default for scanner vulnerabilities
            'is_mitre': 1,  # Default for scanner vulnerabilities
            'year_2023': 0,  # Default for current year
            'year_2024': 0,  # Default for current year
            'cvss_score': 5.0  # Default medium severity score
        }
    
    def _generate_ml_summary(self, enhanced_vulnerabilities: List[Dict]) -> Dict:
        """Generate ML analysis summary"""
        try:
            ml_analyzed = [v for v in enhanced_vulnerabilities if v.get('ml_analysis', {}).get('model_used', False)]
            
            if not ml_analyzed:
                return {'ml_analysis_available': False}
            
            # Calculate statistics
            confidences = [v['ml_analysis']['confidence'] for v in ml_analyzed]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            high_confidence_count = len([c for c in confidences if c > 0.8])
            
            # Count severity changes
            severity_changes = 0
            for vuln in ml_analyzed:
                ml_severity = vuln.get('ml_enhanced_severity')
                original_severity = vuln.get('original_severity')
                if ml_severity and ml_severity != original_severity:
                    severity_changes += 1
            
            return {
                'ml_analysis_available': True,
                'vulnerabilities_analyzed': len(ml_analyzed),
                'average_confidence': avg_confidence,
                'high_confidence_predictions': high_confidence_count,
                'severity_adjustments': severity_changes,
                'model_metadata': self.model_metadata.to_dict() if self.model_metadata else {}
            }
            
        except Exception as e:
            logger.error(f"Error generating ML summary: {e}")
            return {'ml_analysis_available': False, 'error': str(e)}
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get current model status and information"""
        try:
            available_years = self.cve_processor.get_available_years()
            
            # Check if model files exist
            model_files_exist = all([
                (self.models_path / f).exists() for f in [
                    "vulnerability_classifier.pkl",
                    "feature_vectorizer.pkl", 
                    "model_metadata.json",
                    "feature_columns.json"
                ]
            ])
            
            # Try to load model if files exist but model isn't loaded
            model_loaded = self.model is not None
            if model_files_exist and not model_loaded:
                logger.info("Model files found but not loaded, attempting to load model...")
                model_loaded = self.load_trained_model()
            
            status = {
                'model_loaded': model_loaded,
                'available_cve_years': available_years,
                'cve_data_path': str(self.cve_data_path),
                'processed_data_exists': (self.processed_path / "training_dataset.json").exists(),
                'model_files_exist': model_files_exist
            }
            
            if model_loaded and self.model_metadata:
                status['model_info'] = {
                    'training_date': self.model_metadata.training_date,
                    'test_accuracy': self.model_metadata.test_accuracy,
                    'training_samples': self.model_metadata.training_samples,
                    'cve_sources': self.model_metadata.cve_sources
                }
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting model status: {e}")
            return {'error': str(e)}


# Production-ready training script
def main():
    """Main training pipeline for production use"""
    print("🤖 ML Vulnerability Handler - Production Training Pipeline")
    print("=" * 70)
    
    try:
        # Initialize ML handler
        ml_handler = MLVulnerabilityHandler()
        
        # Check status
        status = ml_handler.get_model_status()
        print(f"📁 CVE Data Path: {status['cve_data_path']}")
        print(f"📅 Available Years: {status['available_cve_years']}")
        print(f"📊 Model Files Exist: {status['model_files_exist']}")
        
        if not status['available_cve_years']:
            print("❌ No CVE data available. Please ensure CVE files are in the correct directory structure.")
            return
        
        # Step 1: Collect and process CVE data
        print(f"\n[1/4] Collecting CVE data...")
        if not ml_handler.collect_and_process_cve_data():
            print("❌ Failed to collect CVE data")
            return
        
        # Step 2: Prepare training data
        print(f"\n[2/4] Preparing training data...")
        if not ml_handler.prepare_training_data():
            print("❌ Failed to prepare training data")
            return
        
        # Step 3: Train model
        print(f"\n[3/4] Training vulnerability classifier...")
        if not ml_handler.train_vulnerability_classifier():
            print("❌ Failed to train model")
            return
        
        # Step 4: Save model
        print(f"\n[4/4] Saving trained model...")
        if ml_handler.save_trained_model():
            print("✅ ML model training pipeline completed successfully!")
            print(f"📁 Model saved in: {ml_handler.models_path}")
            
            # Display final status
            final_status = ml_handler.get_model_status()
            if 'model_info' in final_status:
                info = final_status['model_info']
                print(f"\n📊 Model Information:")
                print(f"   • Training Date: {info['training_date']}")
                print(f"   • Test Accuracy: {info['test_accuracy']:.3f}")
                print(f"   • Training Samples: {info['training_samples']:,}")
                print(f"   • CVE Sources: {', '.join(info['cve_sources'])}")
        else:
            print("❌ Failed to save model")
    
    except KeyboardInterrupt:
        print(f"\n⚠️ Training interrupted by user")
    except Exception as e:
        logger.error(f"Training pipeline failed: {e}")
        print(f"❌ Training pipeline failed: {e}")


if __name__ == "__main__":
    main()
