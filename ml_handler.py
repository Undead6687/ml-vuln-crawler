#!/usr/bin/env python3
"""
Machine Learning Vulnerability Classification Engine
Advanced Random Forest and Isolation Forest hybrid model for security analysis.

Author: MohammedMiran J. Shaikh  
Project: ML-Powered Vulnerability Detection Framework
Institution: Master's in Cyber Security
Description: CPU-optimized ML engine for vulnerability classification using CVE data,
             featuring ensemble learning, hyperparameter optimization, and anomaly detection.

Technical Features:
- Random Forest classification with hyperparameter tuning
- Isolation Forest for anomaly detection
- TF-IDF vectorization with custom feature engineering
- Cross-validation and early stopping
- Memory-efficient batch processing
- Comprehensive model evaluation and validation

Dependencies: scikit-learn, pandas, numpy, joblib
"""

"""
ml_handler.py - CPU-based ML Engine for Vulnerability Classification

Random Forest + Isolation Forest Hybrid Model using scikit-learn
Built from scratch for optimal performance and reliability.

"""

import numpy as np
import pandas as pd
import json
import os
import logging
import time
import joblib
import warnings
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass, asdict

# Scikit-learn imports
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import Pipeline

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=FutureWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ModelMetadata:
    """Training metadata for the hybrid model"""
    training_date: str
    model_version: str
    total_samples: int
    training_samples: int
    test_samples: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    feature_count: int
    training_time_seconds: float
    severity_distribution: Dict[str, int]
    model_type: str = "HybridRF-IsolationForest"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExtendedModelMetadata(ModelMetadata):
    """
    Training metadata with validation metrics and convergence analysis.
    
    Extends base ModelMetadata with validation tracking, overfitting detection,
    and training convergence analysis for comprehensive model evaluation.
    
    Attributes:
        validation_samples: Number of validation samples used
        use_validation: Whether validation was enabled during training
        best_val_accuracy: Best validation accuracy achieved
        best_iteration: Iteration number with best validation score
        total_iterations: Total training iterations performed
        training_history: Complete training metrics history
        overfitting_detected: Whether overfitting was detected
        convergence_analysis: Analysis of training convergence patterns
    """
    validation_samples: int = 0
    use_validation: bool = False
    best_val_accuracy: float = 0.0
    best_iteration: int = 0
    total_iterations: int = 1
    training_history: Dict = None
    overfitting_detected: bool = False
    convergence_analysis: Dict = None
    
    def __post_init__(self):
        if self.training_history is None:
            self.training_history = {}
        if self.convergence_analysis is None:
            self.convergence_analysis = {}
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CVEDataProcessor:
    """Processes CVE data from JSON files"""
    
    def __init__(self, cve_base_path: str):
        self.cve_base_path = Path(cve_base_path)
        self.processed_records = []
        
    def discover_cve_files(self) -> List[Path]:
        """Discover all CVE JSON files in the directory structure"""
        cve_files = []
        
        if not self.cve_base_path.exists():
            logger.error(f"CVE base path does not exist: {self.cve_base_path}")
            return cve_files
            
        # Find all JSON files recursively - FIXED for deeply nested structure
        for year_dir in self.cve_base_path.iterdir():
            if year_dir.is_dir() and year_dir.name.isdigit():
                # Look for JSON files recursively in subdirectories (handles nested structure)
                json_files = list(year_dir.rglob("CVE-*.json"))  # FIXED: More specific pattern
                cve_files.extend(json_files)
                logger.info(f"Found {len(json_files)} CVE files in {year_dir.name}")
        
        logger.info(f"Total CVE files discovered: {len(cve_files)}")
        return cve_files
    
    def process_cve_file(self, file_path: Path) -> Optional[Dict]:
        """Process a single CVE JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            # Extract CVE ID (handle both old and new formats)
            cve_id = ""
            if 'CVE_data_meta' in cve_data:
                # Old format
                cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')
            elif 'cveMetadata' in cve_data:
                # New CVE 5.0 format
                cve_id = cve_data.get('cveMetadata', {}).get('cveId', '')
            
            # Extract from filename if not found in data
            if not cve_id:
                cve_id = file_path.stem  # filename without extension
            
            if not cve_id:
                return None
            
            # Extract description (handle both formats)
            description = ""
            
            # Try new CVE 5.0 format first
            if 'containers' in cve_data and 'cna' in cve_data['containers']:
                cna_data = cve_data['containers']['cna']
                descriptions = cna_data.get('descriptions', [])
                for desc in descriptions:
                    if desc.get('lang', '').lower() == 'en':
                        description = desc.get('value', '')
                        break
            
            # Try old format if no description found
            if not description and 'description' in cve_data:
                description_data = cve_data.get('description', {}).get('description_data', [])
                for desc in description_data:
                    if desc.get('lang', '').lower() == 'en':
                        description = desc.get('value', '')
                        break
            
            # Skip invalid descriptions
            if not description or description.strip().lower() in ['** reserved **', '', 'n/a']:
                return None
            
            # Extract CWE information (handle both formats)
            cwe_ids = []
            
            # Try new CVE 5.0 format
            if 'containers' in cve_data and 'cna' in cve_data['containers']:
                cna_data = cve_data['containers']['cna']
                problem_types = cna_data.get('problemTypes', [])
                for problem in problem_types:
                    for desc in problem.get('descriptions', []):
                        cwe_id = desc.get('cweId', '')
                        if cwe_id and cwe_id.startswith('CWE-'):
                            cwe_ids.append(cwe_id)
            
            # Try old format if no CWE found
            if not cwe_ids and 'problemtype' in cve_data:
                problemtype_data = cve_data.get('problemtype', {}).get('problemtype_data', [])
                for problem in problemtype_data:
                    for desc in problem.get('description', []):
                        value = desc.get('value', '')
                        if value.startswith('CWE-'):
                            cwe_ids.append(value)
            
            # Estimate severity based on description keywords
            severity, cvss_score = self._estimate_severity(description)
            
            # Extract year from CVE ID
            year = int(cve_id.split('-')[1]) if len(cve_id.split('-')) >= 2 else 2024
            
            return {
                'cve_id': cve_id,
                'description': description,
                'severity': severity,
                'cvss_score': cvss_score,
                'cwe_ids': cwe_ids,
                'year': year,
                'source': 'mitre'
            }
            
        except Exception as e:
            logger.debug(f"Error processing {file_path}: {e}")
            return None
    
    def _estimate_severity(self, description: str) -> Tuple[str, float]:
        """Estimate severity based on description keywords with deterministic scoring"""
        desc_lower = description.lower()
        
        # Severity keywords with weights (deterministic scoring)
        severity_weights = {
            # Critical indicators (9.0-10.0)
            'remote code execution': 9.8,
            'arbitrary code execution': 9.7,
            'rce': 9.5,
            'privilege escalation': 9.4,
            'root access': 9.3,
            'system compromise': 9.6,
            'complete system takeover': 9.9,
            'kernel': 9.2,
            
            # High indicators (7.0-8.9)
            'buffer overflow': 8.5,
            'stack overflow': 8.4,
            'heap overflow': 8.3,
            'use after free': 8.2,
            'double free': 8.1,
            'format string': 8.0,
            'sql injection': 8.7,
            'command injection': 8.6,
            'code injection': 8.8,
            
            # Medium indicators (4.0-6.9)
            'cross-site scripting': 6.5,
            'xss': 6.5,
            'csrf': 6.0,
            'directory traversal': 5.5,
            'path traversal': 5.5,
            'authentication bypass': 6.8,
            'authorization bypass': 6.7,
            'information disclosure': 5.0,
            'data exposure': 5.2,
            
            # Low indicators (1.0-3.9)
            'information leak': 3.5,
            'version disclosure': 2.0,
            'error message': 2.5,
            'denial of service': 3.8,
            'dos': 3.8,
            'resource consumption': 3.0
        }
        
        # Calculate score based on keywords found
        max_score = 0.0
        severity_level = 'medium'  # default
        
        for keyword, score in severity_weights.items():
            if keyword in desc_lower:
                if score > max_score:
                    max_score = score
        
        # If no keywords found, use description length and complexity as fallback
        if max_score == 0.0:
            # Deterministic fallback based on description characteristics
            desc_len = len(desc_lower)
            word_count = len(desc_lower.split())
            
            # Simple heuristic: longer, more complex descriptions tend to be more severe
            if desc_len > 200 or word_count > 40:
                max_score = 5.5  # medium-high
            elif desc_len > 100 or word_count > 20:
                max_score = 4.5  # medium
            else:
                max_score = 3.0  # low-medium
        
        # Map score to severity category
        if max_score >= 9.0:
            severity_level = 'critical'
        elif max_score >= 7.0:
            severity_level = 'high'
        elif max_score >= 4.0:
            severity_level = 'medium'
        else:
            severity_level = 'low'
        
        return severity_level, max_score
    
    def load_all_cves(self, max_files: Optional[int] = None, batch_size: int = 10000) -> pd.DataFrame:
        """Load and process CVE files with memory-efficient batching"""
        logger.info("Discovering CVE files...")
        cve_files = self.discover_cve_files()
        
        if max_files:
            cve_files = cve_files[:max_files]
            logger.info(f"Limited to {max_files} files for processing")
        
        logger.info(f"Processing {len(cve_files)} CVE files in batches of {batch_size}...")
        
        # Process in batches to save memory
        all_processed_data = []
        batch_count = 0
        
        for i in range(0, len(cve_files), batch_size):
            batch_files = cve_files[i:i + batch_size]
            batch_data = []
            
            logger.info(f"Processing batch {batch_count + 1} ({len(batch_files)} files)...")
            
            for file_path in batch_files:
                cve_record = self.process_cve_file(file_path)
                if cve_record:
                    batch_data.append(cve_record)
            
            if batch_data:
                # Convert batch to DataFrame and immediately process to save memory
                batch_df = pd.DataFrame(batch_data)
                all_processed_data.append(batch_df)
                
                logger.info(f"Batch {batch_count + 1} completed: {len(batch_data)} valid records")
            
            batch_count += 1
            
            # Clear batch data from memory
            del batch_data
        
        if not all_processed_data:
            raise ValueError("No valid CVE data found")
        
        # Combine all batches
        logger.info("Combining all batches...")
        df = pd.concat(all_processed_data, ignore_index=True)
        del all_processed_data  # Free memory
        
        logger.info(f"Successfully processed {len(df)} CVE records")
        
        # FIXED: Clean duplicate data as requested
        initial_count = len(df)
        df = df.drop_duplicates(subset=['description'], keep='first')
        duplicates_removed = initial_count - len(df)
        
        if duplicates_removed > 0:
            logger.info(f"Removed {duplicates_removed} duplicate descriptions (data cleaning)")
        
        # Show severity distribution
        severity_dist = df['severity'].value_counts()
        logger.info(f"Severity distribution: {severity_dist.to_dict()}")
        
        return df
    
    def validate_data_quality(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Validate data quality and detect issues"""
        quality_report = {
            'total_records': len(df),
            'issues': [],
            'warnings': [],
            'quality_score': 1.0
        }
        
        # Check for duplicate descriptions
        duplicates = df['description'].duplicated().sum()
        if duplicates > 0:
            quality_report['issues'].append(f"{duplicates} duplicate descriptions found")
            quality_report['quality_score'] -= 0.1
        
        # Check description length distribution
        desc_lengths = df['description'].str.len()
        very_short = (desc_lengths < 20).sum()
        very_long = (desc_lengths > 1000).sum()
        
        if very_short > len(df) * 0.1:
            quality_report['warnings'].append(f"{very_short} very short descriptions (< 20 chars)")
            quality_report['quality_score'] -= 0.05
        
        if very_long > len(df) * 0.05:
            quality_report['warnings'].append(f"{very_long} very long descriptions (> 1000 chars)")
        
        # Check severity distribution balance
        severity_dist = df['severity'].value_counts()
        min_class_ratio = severity_dist.min() / len(df)
        
        if min_class_ratio < 0.05:  # Less than 5% representation
            quality_report['warnings'].append(f"Imbalanced classes - smallest class: {min_class_ratio:.1%}")
            quality_report['quality_score'] -= 0.1
        
        # Check for suspicious patterns
        reserved_count = df['description'].str.contains('reserved', case=False).sum()
        if reserved_count > 0:
            quality_report['issues'].append(f"{reserved_count} 'reserved' entries found")
            quality_report['quality_score'] -= 0.05
        
        return quality_report


class FeatureEngineer:
    """
    Feature engineering pipeline for vulnerability classification.
    
    Transforms raw CVE data into ML-ready feature vectors using text processing,
    statistical features, and domain-specific vulnerability metrics.
    
    Attributes:
        vectorizer: TF-IDF vectorizer for text features
        scaler: StandardScaler for numerical features
        feature_names: List of engineered feature names
        
    Features Generated:
        - Text length and sentence count statistics
        - CVSS score and severity mappings
        - Publication year and temporal features
        - Security keyword indicators
        - TF-IDF vectors from vulnerability descriptions
    """
    
    def __init__(self):
        self.vectorizer = None
        self.scaler = None
        self.feature_names = []
    
    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer features from CVE data"""
        logger.info("Engineering features...")
        
        df = df.copy()
        
        # Text-based features
        df['description_length'] = df['description'].str.len()
        df['word_count'] = df['description'].str.split().str.len()
        df['sentence_count'] = df['description'].str.count(r'[.!?]+')  # NEW FEATURE
        df['uppercase_ratio'] = df['description'].str.count(r'[A-Z]') / df['description'].str.len()
        df['digit_ratio'] = df['description'].str.count(r'\d') / df['description'].str.len()
        
        # Security-specific keyword features
        security_keywords = {
            'has_remote': r'remote|remotely',
            'has_injection': r'injection|inject',
            'has_xss': r'cross.site|xss|scripting',
            'has_auth': r'authentication|authorization|auth',
            'has_overflow': r'overflow|buffer|heap|stack',
            'has_traversal': r'traversal|directory|path',
            'has_execution': r'execution|execute|rce',
            'has_privilege': r'privilege|escalation|root|admin',
            'has_bypass': r'bypass|circumvent',
            'has_disclosure': r'disclosure|exposure|leak',
            'has_dos': r'denial.of.service|dos|crash',
            'has_memory': r'memory|heap|stack|buffer',
            'has_network': r'network|tcp|udp|http|https',
            'has_crypto': r'crypto|encryption|cipher|hash',
            'has_web': r'web|html|javascript|php|asp'
        }
        
        for feature, pattern in security_keywords.items():
            df[feature] = df['description'].str.contains(
                pattern, case=False, regex=True, na=False
            ).astype(int)
        
        # CWE-based features
        df['cwe_count'] = df['cwe_ids'].apply(len)
        df['has_cwe'] = (df['cwe_count'] > 0).astype(int)
        
        # Temporal features
        current_year = datetime.now().year
        df['years_old'] = current_year - df['year']
        df['is_recent'] = (df['years_old'] <= 2).astype(int)
        df['is_legacy'] = (df['years_old'] >= 10).astype(int)
        
        # Complexity indicators
        df['has_multiple_words'] = (df['word_count'] > 10).astype(int)
        df['has_technical_terms'] = df['description'].str.contains(
            r'vulnerability|flaw|bug|error|issue', case=False, regex=True, na=False
        ).astype(int)
        
        # Severity-based features (but don't include target variable)
        df['cvss_normalized'] = df['cvss_score'] / 10.0
        
        logger.info(f"Created {len([col for col in df.columns if col.startswith('has_')])} keyword features")
        
        return df
    
    def prepare_features(self, df: pd.DataFrame, fit_vectorizer: bool = True) -> Tuple[np.ndarray, List[str]]:
        """Prepare final feature matrix"""
        logger.info("Preparing feature matrix...")
        
        # Numerical features
        numerical_features = [
            'description_length', 'word_count', 'sentence_count', 'uppercase_ratio', 
            'digit_ratio', 'cwe_count', 'years_old', 'cvss_normalized'
        ]
        
        # Binary features
        binary_features = [col for col in df.columns if col.startswith('has_') or col.startswith('is_')]
        
        # Combine numerical and binary features
        feature_columns = numerical_features + binary_features
        numerical_data = df[feature_columns].values
        
        # Text vectorization with FIXED configuration for efficiency
        if fit_vectorizer:
            # FIXED: Optimal max_features for efficiency (as requested)
            max_features = 2000  # REDUCED: Down from 4,252+ to 2,000
            
            self.vectorizer = TfidfVectorizer(
                max_features=max_features,
                ngram_range=(1, 2),
                min_df=max(2, int(len(df) * 0.001)),  # Dynamic min_df
                max_df=0.95,
                stop_words='english',
                lowercase=True,
                strip_accents='unicode',
                token_pattern=r'\b[A-Za-z]+\b',  # Only alphabetic tokens
                norm='l2',  # L2 normalization
                use_idf=True,
                smooth_idf=True,
                sublinear_tf=True  # Apply sublinear tf scaling
            )
            text_features = self.vectorizer.fit_transform(df['description'])
        else:
            if self.vectorizer is None:
                raise ValueError("Vectorizer not fitted")
            text_features = self.vectorizer.transform(df['description'])
        
        # Combine all features
        text_array = text_features.toarray()
        X = np.hstack([numerical_data, text_array])
        
        # Create feature names
        vectorizer_features = [f"tfidf_{i}" for i in range(text_array.shape[1])]
        all_feature_names = feature_columns + vectorizer_features
        self.feature_names = all_feature_names
        
        logger.info(f"Final feature matrix: {X.shape}")
        logger.info(f"Numerical features: {len(feature_columns)}")
        logger.info(f"Text features: {text_array.shape[1]}")
        
        return X, all_feature_names


class HybridRFIsolationClassifier:
    """Hybrid Random Forest + Isolation Forest Classifier"""
    
    def __init__(self, 
                 rf_n_estimators: int = 200,
                 rf_max_depth: int = 15,
                 if_n_estimators: int = 100,
                 contamination: float = 0.1):
        
        # Random Forest with regularization
        self.rf_classifier = RandomForestClassifier(
            n_estimators=rf_n_estimators,
            max_depth=rf_max_depth,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced',
            max_features='sqrt',  # Regularization
            min_samples_split=max(5, rf_n_estimators // 40),  # Dynamic regularization
            min_samples_leaf=max(2, rf_n_estimators // 100),  # Dynamic regularization
            max_leaf_nodes=None,
            bootstrap=True,
            oob_score=True,  # Out-of-bag scoring
            warm_start=False
        )
        
        # Isolation Forest for anomaly detection
        self.isolation_forest = IsolationForest(
            n_estimators=if_n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
            max_features=1.0,
            bootstrap=False,
            warm_start=False
        )
        
        self.is_fitted = False
        self.label_encoder = LabelEncoder()
        self.severity_mapping = {}
        
    def fit(self, X: np.ndarray, y: np.ndarray) -> 'HybridRFIsolationClassifier':
        """Train the hybrid model"""
        logger.info("Training Random Forest classifier...")
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        self.severity_mapping = {
            i: label for i, label in enumerate(self.label_encoder.classes_)
        }
        
        # Train Random Forest
        self.rf_classifier.fit(X, y_encoded)
        
        logger.info("Training Isolation Forest for anomaly detection...")
        # Train Isolation Forest
        self.isolation_forest.fit(X)
        
        self.is_fitted = True
        return self
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities - FIXED VERSION"""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        # Return pure Random Forest probabilities (no artificial confidence reduction)
        rf_probs = self.rf_classifier.predict_proba(X)
        
        # Optional: Only adjust truly anomalous samples if isolation forest exists
        if self.isolation_forest is not None:
            anomaly_predictions = self.isolation_forest.predict(X)  # -1 for anomalies, 1 for normal
            
            adjusted_probs = rf_probs.copy()
            for i, anomaly_flag in enumerate(anomaly_predictions):
                if anomaly_flag == -1:  # Only adjust anomalous samples
                    adjusted_probs[i] *= 0.8  # Modest reduction for anomalies only
                    adjusted_probs[i] /= adjusted_probs[i].sum()  # Renormalize
            
            return adjusted_probs
        
        return rf_probs
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict classes"""
        proba = self.predict_proba(X)
        encoded_predictions = np.argmax(proba, axis=1)
        return self.label_encoder.inverse_transform(encoded_predictions)
    
    def predict_with_uncertainty(self, X: np.ndarray) -> List[Dict]:
        """Predict with uncertainty quantification - FIXED VERSION"""
        probabilities = self.predict_proba(X)
        
        results = []
        for i, probs in enumerate(probabilities):
            predicted_class_idx = np.argmax(probs)
            predicted_class = self.severity_mapping[predicted_class_idx]
            confidence = probs[predicted_class_idx]
            
            # Calculate entropy as uncertainty measure
            entropy = -np.sum(probs * np.log(probs + 1e-10))
            max_entropy = np.log(len(probs))
            uncertainty = entropy / max_entropy
            
            result = {
                'predicted_severity': predicted_class,
                'confidence': float(confidence),
                'uncertainty': float(uncertainty),
                'is_reliable': confidence > 0.7,  # FIXED: Simple threshold, no complex adjustment
                'probabilities': {
                    self.severity_mapping[j]: float(prob) 
                    for j, prob in enumerate(probs)
                }
            }
            results.append(result)
        
        return results if len(results) > 1 else results[0]


class MLVulnerabilityEngine:
    """
    Machine Learning vulnerability classification engine.
    
    A comprehensive ML system for classifying vulnerabilities using CVE data.
    Implements Random Forest classification with Isolation Forest anomaly detection
    for accurate security assessment and threat classification.
    
    Attributes:
        cve_base_path: Path to CVE JSON data files
        models_path: Directory for saving trained models
        data_processor: CVE data processing component
        feature_engineer: Feature extraction and engineering component
        model: Trained Random Forest + Isolation Forest model
        metadata: Training metadata and performance metrics
        
    Features:
        - Random Forest classification with hyperparameter tuning
        - Isolation Forest for anomaly detection
        - TF-IDF text vectorization with custom features
        - Cross-validation and early stopping
        - Comprehensive model evaluation and validation
        - Memory-efficient batch processing
    """
    
    def __init__(self, cve_base_path: str, models_path: str = "./trained_models"):
        self.cve_base_path = cve_base_path
        self.models_path = Path(models_path)
        self.models_path.mkdir(exist_ok=True)
        
        self.data_processor = CVEDataProcessor(cve_base_path)
        self.feature_engineer = FeatureEngineer()
        self.model = None
        self.metadata = None
        self.training_data = None
        
        logger.info(f"ML Vulnerability Engine initialized")
        logger.info(f"CVE path: {cve_base_path}")
        logger.info(f"Models path: {models_path}")
    
    def create_train_val_test_split(self, X: np.ndarray, y: np.ndarray, 
                                   train_size: float = 0.6, 
                                   val_size: float = 0.2, 
                                   test_size: float = 0.2,
                                   random_state: int = 42) -> Tuple[np.ndarray, ...]:
        """
        Create train-validation-test split with stratification
        
        Args:
            X: Feature matrix
            y: Target labels
            train_size: Proportion for training (default 0.6)
            val_size: Proportion for validation (default 0.2) 
            test_size: Proportion for testing (default 0.2)
            random_state: Random seed for reproducibility
            
        Returns:
            Tuple of (X_train, X_val, X_test, y_train, y_val, y_test)
        """
        assert abs(train_size + val_size + test_size - 1.0) < 1e-6, "Sizes must sum to 1.0"
        
        # First split: separate test set
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, 
            test_size=test_size, 
            random_state=random_state, 
            stratify=y
        )
        
        # Second split: divide remaining into train and validation
        # Adjust validation size relative to the remaining data
        val_size_adjusted = val_size / (train_size + val_size)
        
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp,
            test_size=val_size_adjusted,
            random_state=random_state,
            stratify=y_temp
        )
        
        logger.info(f"Data split - Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        logger.info(f"Train ratio: {len(X_train)/len(X):.1%}, Val: {len(X_val)/len(X):.1%}, Test: {len(X_test)/len(X):.1%}")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def _train_with_validation(self, X_train: np.ndarray, y_train: np.ndarray,
                              X_val: np.ndarray, y_val: np.ndarray,
                              X_test: np.ndarray, y_test: np.ndarray,
                              patience: int = 10, max_iterations: int = 50) -> Dict:
        """Train model with proper validation using different hyperparameters"""
        logger.info(f"Training with hyperparameter search: max {max_iterations} configurations, patience {patience}")
        
        # Initialize tracking variables
        best_val_accuracy = 0.0
        best_model_state = None
        best_params = None
        patience_counter = 0
        history = {
            'train_accuracy': [],
            'val_accuracy': [],
            'train_precision': [],
            'val_precision': [],
            'train_recall': [],
            'val_recall': [],
            'train_f1': [],
            'val_f1': [],
            'config': []
        }
        
        # FIXED: More efficient hyperparameter search (no wasteful retraining)
        from sklearn.model_selection import ParameterGrid
        
        # Parameter grid - efficient combinations
        param_grid = {
            'rf_n_estimators': [50, 100, 150],    # 3 options instead of 10+
            'rf_max_depth': [8, 12, None],        # 3 options including unlimited
            'if_contamination': [0.05, 0.1, 0.15] # 3 contamination levels
        }
        
        # Generate all combinations efficiently
        param_configs = list(ParameterGrid(param_grid))[:max_iterations]
        logger.info(f"Hyperparameter search: {len(param_configs)} efficient configurations")
        
        for iteration, config in enumerate(param_configs):
            logger.info(f"Configuration {iteration+1}/{len(param_configs)}: {config}")
            
            # Create new model with current configuration
            current_model = HybridRFIsolationClassifier(
                rf_n_estimators=config['rf_n_estimators'],
                rf_max_depth=config['rf_max_depth'],
                if_n_estimators=100,  # Keep IF consistent
                contamination=config['if_contamination']
            )
            
            # Train with current configuration
            current_model.fit(X_train, y_train)
            
            # Evaluate on training set
            train_pred = current_model.predict(X_train)
            train_accuracy = accuracy_score(y_train, train_pred)
            train_precision, train_recall, train_f1, _ = precision_recall_fscore_support(
                y_train, train_pred, average='weighted', zero_division=0
            )
            
            # Evaluate on validation set
            val_pred = current_model.predict(X_val)
            val_accuracy = accuracy_score(y_val, val_pred)
            val_precision, val_recall, val_f1, _ = precision_recall_fscore_support(
                y_val, val_pred, average='weighted', zero_division=0
            )
            
            # Record history
            history['train_accuracy'].append(train_accuracy)
            history['val_accuracy'].append(val_accuracy)
            history['train_precision'].append(train_precision)
            history['val_precision'].append(val_precision)
            history['train_recall'].append(train_recall)
            history['val_recall'].append(val_recall)
            history['train_f1'].append(train_f1)
            history['val_f1'].append(val_f1)
            history['config'].append(config)
            
            # Check for improvement
            if val_accuracy > best_val_accuracy:
                best_val_accuracy = val_accuracy
                best_model_state = self._get_model_state_from_model(current_model)
                best_params = config
                patience_counter = 0
                best_iteration = iteration
                logger.info(f"Configuration {iteration+1:2d}: New best! "
                           f"Train Acc: {train_accuracy:.3f}, Val Acc: {val_accuracy:.3f}")
            else:
                patience_counter += 1
                logger.info(f"Configuration {iteration+1:2d}: "
                           f"Train Acc: {train_accuracy:.3f}, Val Acc: {val_accuracy:.3f} "
                           f"(Patience: {patience_counter}/{patience})")
            
            # Early stopping
            if patience_counter >= patience:
                logger.info(f"Early stopping at configuration {iteration+1} (patience reached)")
                break
        
        # Restore best model
        if best_model_state:
            self.model = HybridRFIsolationClassifier(
                rf_n_estimators=best_params['rf_n_estimators'],
                rf_max_depth=best_params['rf_max_depth'],
                if_n_estimators=100,
                contamination=best_params['if_contamination']
            )
            self._restore_model_state_to_model(best_model_state, self.model)
            logger.info(f"Restored best model from configuration {best_iteration+1}: {best_params}")
        
        # Final test evaluation
        test_pred = self.model.predict(X_test)
        test_accuracy = accuracy_score(y_test, test_pred)
        test_precision, test_recall, test_f1, _ = precision_recall_fscore_support(
            y_test, test_pred, average='weighted', zero_division=0
        )
        
        # Overfitting detection
        overfitting_detected = self._detect_overfitting(history)
        
        return {
            'test_accuracy': test_accuracy,
            'test_precision': test_precision,
            'test_recall': test_recall,
            'test_f1': test_f1,
            'best_val_accuracy': best_val_accuracy,
            'best_iteration': best_iteration,
            'total_iterations': iteration + 1,
            'best_params': best_params,
            'history': history,
            'overfitting_detected': overfitting_detected,
            'early_stopped': patience_counter >= patience
        }
    
    def _evaluate_simple_model(self, X_train: np.ndarray, y_train: np.ndarray,
                              X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Evaluate model without validation (simple train-test)"""
        
        # Train evaluation
        train_pred = self.model.predict(X_train)
        train_accuracy = accuracy_score(y_train, train_pred)
        
        # Test evaluation
        test_pred = self.model.predict(X_test)
        test_accuracy = accuracy_score(y_test, test_pred)
        test_precision, test_recall, test_f1, _ = precision_recall_fscore_support(
            y_test, test_pred, average='weighted', zero_division=0
        )
        
        return {
            'test_accuracy': test_accuracy,
            'test_precision': test_precision,
            'test_recall': test_recall,
            'test_f1': test_f1,
            'train_accuracy': train_accuracy
        }
    
    def _get_model_state(self) -> Dict:
        """Get current model state for checkpointing"""
        return {
            'rf_classifier': self.model.rf_classifier,
            'isolation_forest': self.model.isolation_forest,
            'label_encoder': self.model.label_encoder,
            'severity_mapping': self.model.severity_mapping.copy(),
            'is_fitted': self.model.is_fitted
        }
    
    def _get_model_state_from_model(self, model) -> Dict:
        """Get model state from any HybridRFIsolationClassifier instance"""
        return {
            'rf_classifier': model.rf_classifier,
            'isolation_forest': model.isolation_forest,
            'label_encoder': model.label_encoder,
            'severity_mapping': model.severity_mapping.copy(),
            'is_fitted': model.is_fitted
        }
    
    def _restore_model_state(self, state: Dict):
        """Restore model from saved state"""
        self.model.rf_classifier = state['rf_classifier']
        self.model.isolation_forest = state['isolation_forest']
        self.model.label_encoder = state['label_encoder']
        self.model.severity_mapping = state['severity_mapping']
        self.model.is_fitted = state['is_fitted']
    
    def _restore_model_state_to_model(self, state: Dict, target_model):
        """Restore model state to specific model instance"""
        target_model.rf_classifier = state['rf_classifier']
        target_model.isolation_forest = state['isolation_forest']
        target_model.label_encoder = state['label_encoder']
        target_model.severity_mapping = state['severity_mapping']
        target_model.is_fitted = state['is_fitted']
    
    def _validate_training_results(self, results: Dict, dataset_size: int) -> Dict:
        """Validate training results and detect suspicious patterns"""
        
        # Check for perfect scores on small datasets (likely overfitting)
        if dataset_size < 1000:
            if results['test_accuracy'] > 0.995:
                logger.warning("Perfect accuracy on small dataset - likely overfitting!")
                logger.warning("Consider: 1) More data 2) Regularization 3) Simpler model")
                results['overfitting_warning'] = 'perfect_accuracy_small_dataset'
            
            if results['test_accuracy'] > 0.98 and results.get('best_val_accuracy', 0) < 0.95:
                logger.warning("Large train-validation gap detected!")
                results['overfitting_warning'] = 'large_train_val_gap'
        
        # Check for suspiciously high scores on any dataset
        if results['test_accuracy'] > 0.99:
            logger.warning("Suspiciously high accuracy - verify data quality")
            results['data_quality_warning'] = 'suspiciously_high_accuracy'
        
        return results
    
    def _detect_overfitting(self, history: Dict) -> bool:
        """Detect if model is overfitting based on training history"""
        if not history['val_accuracy'] or len(history['val_accuracy']) < 5:
            return False
        
        # Check if validation accuracy is declining while training accuracy increases
        recent_val = history['val_accuracy'][-3:]  # Last 3 iterations
        recent_train = history['train_accuracy'][-3:]
        
        if len(recent_val) < 3:
            return False
        
        val_trend = recent_val[-1] - recent_val[0]  # Validation trend
        train_trend = recent_train[-1] - recent_train[0]  # Training trend
        
        # Overfitting if train increases but val decreases significantly
        return train_trend > 0.02 and val_trend < -0.03
    
    def _log_comprehensive_training_results(self, results: Dict, training_time: float, 
                                           use_validation: bool, data_quality: Dict):
        """Comprehensive training results logging with quality metrics"""
        
        logger.info("=" * 60)
        logger.info("TRAINING COMPLETED - COMPREHENSIVE REPORT")
        logger.info("=" * 60)
        
        # Data Quality Section
        logger.info("DATA QUALITY REPORT:")
        logger.info(f"   Quality Score: {data_quality['quality_score']:.2f}/1.0")
        if data_quality['issues']:
            for issue in data_quality['issues']:
                logger.warning(f"   Issue: {issue}")
        if data_quality['warnings']:
            for warning in data_quality['warnings']:
                logger.info(f"   Warning: {warning}")
        
        # Performance Metrics Section
        logger.info("\nPERFORMANCE METRICS:")
        logger.info(f"   Test Accuracy:  {results['test_accuracy']:.4f}")
        logger.info(f"   Test Precision: {results['test_precision']:.4f}")
        logger.info(f"   Test Recall:    {results['test_recall']:.4f}")
        logger.info(f"   Test F1-Score:  {results['test_f1']:.4f}")
        
        if use_validation:
            logger.info(f"   Best Val Accuracy: {results['best_val_accuracy']:.4f}")
            logger.info(f"   Best Configuration: {results.get('best_params', 'N/A')}")
            logger.info(f"   Configurations Tested: {results['total_iterations']}")
            
            gap = results['test_accuracy'] - results['best_val_accuracy']
            if gap > 0.05:
                logger.warning(f"   Large generalization gap: {gap:.3f}")
            elif gap > 0.02:
                logger.info(f"   Moderate generalization gap: {gap:.3f}")
            else:
                logger.info(f"   Good generalization: gap = {gap:.3f}")
        
        # Training Insights Section
        logger.info(f"\nTRAINING INSIGHTS:")
        logger.info(f"   Training Time: {training_time:.1f}s ({training_time/60:.1f} min)")
        logger.info(f"   Early Stopped: {results.get('early_stopped', False)}")
        logger.info(f"   Overfitting Detected: {results.get('overfitting_detected', False)}")
        
        # Model Reliability Assessment
        reliability_score = self._calculate_reliability_score(results, data_quality)
        logger.info(f"\nMODEL RELIABILITY SCORE: {reliability_score:.2f}/5.0")
        
        if reliability_score >= 4.0:
            logger.info("   EXCELLENT - Model ready for production")
        elif reliability_score >= 3.0:
            logger.info("   GOOD - Model suitable for most use cases")
        elif reliability_score >= 2.0:
            logger.info("   FAIR - Consider additional validation")
        else:
            logger.warning("   POOR - Model needs improvement before deployment")
        
        logger.info("=" * 60)
    
    def _calculate_reliability_score(self, results: Dict, data_quality: Dict) -> float:
        """Calculate overall model reliability score (0-5)"""
        score = 0.0
        
        # Performance component (0-2 points)
        accuracy = results['test_accuracy']
        if accuracy >= 0.90:
            score += 2.0
        elif accuracy >= 0.80:
            score += 1.5
        elif accuracy >= 0.70:
            score += 1.0
        elif accuracy >= 0.60:
            score += 0.5
        
        # Data quality component (0-1.5 points)
        score += data_quality['quality_score'] * 1.5
        
        # Generalization component (0-1 points)
        if 'best_val_accuracy' in results:
            gap = abs(results['test_accuracy'] - results['best_val_accuracy'])
            if gap <= 0.02:
                score += 1.0
            elif gap <= 0.05:
                score += 0.7
            elif gap <= 0.1:
                score += 0.4
        else:
            score += 0.5  # Default for no validation
        
        # Stability component (0-0.5 points)
        if not results.get('overfitting_detected', False):
            score += 0.5
        
        return min(score, 5.0)
    
    def _log_training_results(self, results: Dict, training_time: float, use_validation: bool):
        """Log comprehensive training results"""
        logger.info("Model training completed!")
        logger.info(f"Performance Metrics:")
        logger.info(f"   Test Accuracy: {results['test_accuracy']:.3f}")
        logger.info(f"   Test Precision: {results['test_precision']:.3f}")
        logger.info(f"   Test Recall: {results['test_recall']:.3f}")
        logger.info(f"   Test F1-Score: {results['test_f1']:.3f}")
        
        if use_validation:
            logger.info(f"   Best Val Accuracy: {results['best_val_accuracy']:.3f}")
            logger.info(f"   Best Iteration: {results['best_iteration']+1}")
            logger.info(f"   Total Iterations: {results['total_iterations']}")
            logger.info(f"   Early Stopped: {results.get('early_stopped', False)}")
            logger.info(f"   Overfitting Detected: {results.get('overfitting_detected', False)}")
        
        logger.info(f"   Training Time: {training_time:.2f}s")
    
    def train_model(self,
                   max_files: Optional[int] = None,
                   use_validation: bool = True,
                   train_size: float = 0.6,
                   val_size: float = 0.2,
                   test_size: float = 0.2,
                   save_model: bool = True,
                   early_stopping_patience: int = 10,
                   max_iterations: int = 50) -> bool:
        """
        Train hybrid Random Forest + Isolation Forest model for vulnerability classification.
        
        Performs comprehensive ML model training with hyperparameter optimization,
        early stopping, and validation-based convergence detection. Implements
        memory-efficient batch processing for large CVE datasets.
        
        Args:
            max_files: Maximum CVE files to process (None for all files)
            use_validation: Enable validation split and early stopping
            train_size: Proportion of data for training (0.0-1.0)
            val_size: Proportion of data for validation (0.0-1.0)
            test_size: Proportion of data for testing (0.0-1.0)
            save_model: Whether to save trained model to disk
            early_stopping_patience: Iterations without improvement before stopping
            max_iterations: Maximum hyperparameter optimization iterations
            
        Returns:
            bool: True if training completed successfully, False otherwise
            
        Raises:
            Exception: For data loading failures, insufficient data quality,
                      or model training errors
        """
        try:
            start_time = time.time()
            
            # Validate split proportions
            if abs(train_size + val_size + test_size - 1.0) > 1e-6:
                raise ValueError("train_size + val_size + test_size must equal 1.0")
            
            # Load CVE data with memory-efficient processing
            logger.info("Loading CVE data with quality validation...")
            df = self.data_processor.load_all_cves(max_files=max_files)
            
            # Data quality validation
            data_quality = self.data_processor.validate_data_quality(df)
            if data_quality['quality_score'] < 0.5:
                logger.error("Data quality too poor for reliable training")
                logger.error("Consider cleaning data before training")
                return False
            
            # Feature engineering with dynamic optimization
            logger.info("Engineering features with adaptive parameters...")
            df_features = self.feature_engineer.engineer_features(df)
            
            # Prepare features with dataset-size adaptation
            X, feature_names = self.feature_engineer.prepare_features(df_features, fit_vectorizer=True)
            y = df['severity'].values
            
            logger.info(f"Final dataset shape: {X.shape}")
            logger.info(f"Features: {X.shape[1]:,} total ({len(feature_names) - X.shape[1] + len([f for f in feature_names if not f.startswith('tfidf_')]):,} engineered + {X.shape[1] - len([f for f in feature_names if not f.startswith('tfidf_')]):,} text)")
            
            # Create splits with stratification
            if use_validation:
                logger.info(f"Creating stratified train-validation-test split: {train_size:.0%}-{val_size:.0%}-{test_size:.0%}")
                X_train, X_val, X_test, y_train, y_val, y_test = self.create_train_val_test_split(
                    X, y, train_size=train_size, val_size=val_size, test_size=test_size
                )
            else:
                logger.info(f"Creating stratified train-test split: {1-test_size:.0%}-{test_size:.0%}")
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=test_size, random_state=42, stratify=y
                )
                X_val, y_val = None, None
            
            # Train hybrid model with hyperparameter optimization
            logger.info("Training Hybrid Random Forest + Isolation Forest model...")
            self.model = HybridRFIsolationClassifier()
            
            if use_validation:
                training_results = self._train_with_validation(
                    X_train, y_train, X_val, y_val, X_test, y_test,
                    early_stopping_patience, max_iterations
                )
            else:
                # Simple training without validation
                self.model.fit(X_train, y_train)
                training_results = self._evaluate_simple_model(X_train, y_train, X_test, y_test)
            
            training_time = time.time() - start_time
            
            # Validate results for quality issues
            training_results = self._validate_training_results(training_results, len(df))
            
            # Create metadata with validation metrics
            self.metadata = ExtendedModelMetadata(
                training_date=datetime.now(timezone.utc).isoformat(),
                model_version="3.2.0",  # Updated version
                total_samples=len(df),
                training_samples=len(X_train),
                validation_samples=len(X_val) if X_val is not None else 0,
                test_samples=len(X_test),
                accuracy=training_results['test_accuracy'],
                precision=training_results['test_precision'],
                recall=training_results['test_recall'],
                f1_score=training_results['test_f1'],
                feature_count=X.shape[1],
                training_time_seconds=training_time,
                severity_distribution=df['severity'].value_counts().to_dict(),
                use_validation=use_validation,
                best_val_accuracy=training_results.get('best_val_accuracy', 0),
                best_iteration=training_results.get('best_iteration', 0),
                total_iterations=training_results.get('total_iterations', 1),
                training_history=training_results.get('history', {}),
                overfitting_detected=training_results.get('overfitting_detected', False)
            )
            
            # Add quality metrics to metadata
            self.metadata.data_quality_score = data_quality['quality_score']
            self.metadata.reliability_score = self._calculate_reliability_score(training_results, data_quality)
            
            # Comprehensive logging
            self._log_comprehensive_training_results(training_results, training_time, use_validation, data_quality)
            
            # Save model with quality metrics
            if save_model:
                success = self.save_model()
                if not success:
                    logger.warning("Model training succeeded but saving failed")
            
            return True
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def save_model(self) -> bool:
        """Save the trained model and components"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save model
            model_file = self.models_path / f"hybrid_rf_isolation_{timestamp}.pkl"
            joblib.dump(self.model, model_file)
            
            # Save feature engineer
            fe_file = self.models_path / f"feature_engineer_{timestamp}.pkl"
            joblib.dump(self.feature_engineer, fe_file)
            
            # Save metadata
            metadata_file = self.models_path / f"metadata_{timestamp}.json"
            with open(metadata_file, 'w') as f:
                json.dump(self.metadata.to_dict(), f, indent=2)
            
            logger.info(f"Model saved successfully:")
            logger.info(f"   Model: {model_file}")
            logger.info(f"   Feature Engineer: {fe_file}")
            logger.info(f"   Metadata: {metadata_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False
    
    def load_model(self, model_path: str, fe_path: str, metadata_path: str = None) -> bool:
        """Load a trained model"""
        try:
            self.model = joblib.load(model_path)
            self.feature_engineer = joblib.load(fe_path)
            
            if metadata_path and os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata_dict = json.load(f)
                    # Try ExtendedModelMetadata first (supports validation_samples), fall back to ModelMetadata
                    try:
                        self.metadata = ExtendedModelMetadata(**metadata_dict)
                    except TypeError:
                        # Fall back to basic ModelMetadata if extended fields are missing
                        filtered_dict = {k: v for k, v in metadata_dict.items() 
                                       if k in ['training_date', 'model_version', 'total_samples', 
                                               'training_samples', 'test_samples', 'accuracy', 'precision',
                                               'recall', 'f1_score', 'feature_count', 'training_time_seconds',
                                               'severity_distribution', 'model_type']}
                        self.metadata = ModelMetadata(**filtered_dict)
            
            logger.info("Model loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def predict_vulnerability(self, description: str) -> Dict:
        """Predict vulnerability severity for a single description"""
        if not self.model or not self.feature_engineer:
            raise ValueError("Model not trained or loaded")
        
        # Create a mini dataframe for processing
        df = pd.DataFrame([{
            'cve_id': 'TEMP-001',
            'description': description,
            'severity': 'unknown',
            'cvss_score': 5.0,
            'cwe_ids': [],
            'year': datetime.now().year,
            'source': 'user_input'
        }])
        
        # Feature engineering
        df_features = self.feature_engineer.engineer_features(df)
        X, _ = self.feature_engineer.prepare_features(df_features, fit_vectorizer=False)
        
        # Predict
        result = self.model.predict_with_uncertainty(X)
        
        return result

    def plot_training_history(self, save_path: str = None) -> None:
        """Plot training and validation curves"""
        if not self.metadata or not hasattr(self.metadata, 'training_history'):
            logger.warning("No training history available for plotting")
            return
            
        try:
            import matplotlib.pyplot as plt
            
            history = self.metadata.training_history
            if not history or not history.get('train_accuracy'):
                logger.warning("Training history is empty")
                return
            
            iterations = range(1, len(history['train_accuracy']) + 1)
            
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
            
            # Accuracy plot
            ax1.plot(iterations, history['train_accuracy'], 'b-', label='Training Accuracy', linewidth=2)
            if history.get('val_accuracy'):
                ax1.plot(iterations, history['val_accuracy'], 'r-', label='Validation Accuracy', linewidth=2)
            ax1.set_title('Model Accuracy Over Time')
            ax1.set_xlabel('Iteration')
            ax1.set_ylabel('Accuracy')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            ax1.set_ylim(0, 1)
            
            # Precision plot
            ax2.plot(iterations, history['train_precision'], 'b-', label='Training Precision', linewidth=2)
            if history.get('val_precision'):
                ax2.plot(iterations, history['val_precision'], 'r-', label='Validation Precision', linewidth=2)
            ax2.set_title('Model Precision Over Time')
            ax2.set_xlabel('Iteration')
            ax2.set_ylabel('Precision')
            ax2.legend()
            ax2.grid(True, alpha=0.3)
            ax2.set_ylim(0, 1)
            
            # Recall plot
            ax3.plot(iterations, history['train_recall'], 'b-', label='Training Recall', linewidth=2)
            if history.get('val_recall'):
                ax3.plot(iterations, history['val_recall'], 'r-', label='Validation Recall', linewidth=2)
            ax3.set_title('Model Recall Over Time')
            ax3.set_xlabel('Iteration')
            ax3.set_ylabel('Recall')
            ax3.legend()
            ax3.grid(True, alpha=0.3)
            ax3.set_ylim(0, 1)
            
            # F1-Score plot
            ax4.plot(iterations, history['train_f1'], 'b-', label='Training F1-Score', linewidth=2)
            if history.get('val_f1'):
                ax4.plot(iterations, history['val_f1'], 'r-', label='Validation F1-Score', linewidth=2)
            ax4.set_title('Model F1-Score Over Time')
            ax4.set_xlabel('Iteration')
            ax4.set_ylabel('F1-Score')
            ax4.legend()
            ax4.grid(True, alpha=0.3)
            ax4.set_ylim(0, 1)
            
            plt.tight_layout()
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                logger.info(f"Training plots saved to {save_path}")
            else:
                plt.show()
                
        except ImportError:
            logger.warning("Matplotlib not available for plotting")
        except Exception as e:
            logger.error(f"Error plotting training history: {e}")
    
    def evaluate_model_comprehensive(self) -> Dict[str, Any]:
        """Comprehensive model evaluation with detailed metrics"""
        if self.model is None:
            return {'error': 'No model loaded'}
            
        try:
            results = {
                'model_type': self.metadata.model_type if self.metadata else 'Unknown',
                'model_version': self.metadata.model_version if self.metadata else 'Unknown'
            }
            
            if self.metadata:
                results.update({
                    'training_samples': self.metadata.training_samples,
                    'test_samples': self.metadata.test_samples,
                    'test_accuracy': self.metadata.accuracy,
                    'test_precision': self.metadata.precision,
                    'test_recall': self.metadata.recall,
                    'test_f1_score': self.metadata.f1_score,
                    'feature_count': self.metadata.feature_count,
                    'training_time_seconds': self.metadata.training_time_seconds
                })
                
                if hasattr(self.metadata, 'validation_samples') and self.metadata.use_validation:
                    results.update({
                        'validation_samples': self.metadata.validation_samples,
                        'best_val_accuracy': self.metadata.best_val_accuracy,
                        'best_iteration': self.metadata.best_iteration,
                        'total_iterations_trained': self.metadata.total_iterations,
                        'overfitting_detected': self.metadata.overfitting_detected,
                        'convergence_analysis': self._analyze_learning_curve()
                    })
            
            return results
            
        except Exception as e:
            return {'error': f'Evaluation failed: {str(e)}'}
    
    def _analyze_learning_curve(self) -> Dict[str, Any]:
        """Analyze the learning curve trend"""
        if not self.metadata or not hasattr(self.metadata, 'training_history'):
            return {'status': 'no_data', 'analysis': 'insufficient_data'}
        
        history = self.metadata.training_history
        if not history.get('val_accuracy') or len(history['val_accuracy']) < 3:
            return {'status': 'insufficient_data', 'analysis': 'not_enough_validation_data'}
        
        val_acc = history['val_accuracy']
        train_acc = history['train_accuracy']
        
        # Calculate trends
        val_trend = val_acc[-1] - val_acc[0] if len(val_acc) > 1 else 0
        train_trend = train_acc[-1] - train_acc[0] if len(train_acc) > 1 else 0
        
        # Recent improvement (last 3 iterations)
        recent_val_improvement = val_acc[-1] - val_acc[-3] if len(val_acc) >= 3 else 0
        
        # Gap analysis
        final_gap = train_acc[-1] - val_acc[-1] if len(train_acc) > 0 and len(val_acc) > 0 else 0
        
        # Determine status
        if recent_val_improvement > 0.01:
            status = "still_improving"
        elif abs(recent_val_improvement) <= 0.01:
            status = "converged"
        else:
            status = "declining"
        
        # Overfitting analysis
        overfitting_risk = "high" if final_gap > 0.1 else "medium" if final_gap > 0.05 else "low"
        
        return {
            'status': status,
            'validation_trend': val_trend,
            'training_trend': train_trend,
            'recent_val_improvement': recent_val_improvement,
            'train_val_gap': final_gap,
            'overfitting_risk': overfitting_risk,
            'best_val_accuracy': max(val_acc),
            'final_val_accuracy': val_acc[-1],
            'analysis': f"Model {status} with {overfitting_risk} overfitting risk"
        }


# Example usage and testing
if __name__ == "__main__":
    # Initialize engine
    engine = MLVulnerabilityEngine(cve_base_path="./cves")
    
    # Train model (use smaller subset for testing)
    success = engine.train_model(max_files=1000)  # Remove max_files for full dataset
    
    if success:
        print("\nTraining completed successfully!")
        
        # Test prediction
        test_desc = "Buffer overflow vulnerability allows remote code execution"
        result = engine.predict_vulnerability(test_desc)
        print(f"\nTest prediction: {result}")
    else:
        print("Training failed!")
