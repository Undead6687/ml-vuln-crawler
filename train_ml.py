#!/usr/bin/env python3
"""
Web Vulnerability Detection Framework
Author: MohammedMiran J. Shaikh
Project: ML-Driven Web Vulnerability Detection with Dynamic Crawling
Institution: Master of Engineering in Cyber Security - LK473

Description: Machine learning model training module for vulnerability classification.
             Implements Random Forest training with train-validation-test splits and early stopping.
Dependencies: scikit-learn, pandas, numpy, matplotlib, ml_handler
"""

import sys
import os
import argparse
import traceback
from pathlib import Path
from typing import Dict, Any

# Add current directory to Python path
sys.path.append(str(Path(__file__).parent))

try:
    from ml_handler import MLVulnerabilityEngine
except ImportError:
    print("Error: ml_handler.py not found. Make sure you're in the correct directory.")
    sys.exit(1)

def main() -> None:
    """
    Main training function with configurable train-validation-test splits.
    
    Supports both simple train-test splits and full train-validation-test splits
    with early stopping based on validation performance. Implements Random Forest
    classifier training for vulnerability severity classification based on CVE data.
    
    Returns:
        None
    
    Raises:
        ValueError: When split proportions don't sum to 1.0
        KeyboardInterrupt: When training is interrupted by user
        Exception: For general training failures
    """
    parser = argparse.ArgumentParser(description='Machine Learning Model Training with Validation')
    parser.add_argument('--max-files', type=int, help='Limit number of CVE files for testing')
    parser.add_argument('--train-size', type=float, default=0.6, help='Training set proportion (default: 0.6)')
    parser.add_argument('--val-size', type=float, default=0.2, help='Validation set proportion (default: 0.2)')
    parser.add_argument('--test-size', type=float, default=0.2, help='Test set proportion (default: 0.2)')
    parser.add_argument('--no-validation', action='store_true', help='Skip validation (use simple train-test split)')
    parser.add_argument('--patience', type=int, default=10, help='Early stopping patience (default: 10)')
    parser.add_argument('--max-iterations', type=int, default=50, help='Maximum training iterations (default: 50)')
    parser.add_argument('--plot-history', action='store_true', help='Plot training history after training')
    parser.add_argument('--evaluate', action='store_true', help='Run evaluation after training')
    
    args = parser.parse_args()
    
    # Validate split proportions
    if not args.no_validation and abs(args.train_size + args.val_size + args.test_size - 1.0) > 1e-6:
        print("Error: train_size + val_size + test_size must equal 1.0")
        return
    
    print("ML Training with Train-Validation-Test Split")
    print("=" * 70)
    print("Configuration:")
    if not args.no_validation:
        print(f"   Train: {args.train_size:.0%}, Validation: {args.val_size:.0%}, Test: {args.test_size:.0%}")
        print(f"   Early stopping patience: {args.patience}")
        print(f"   Max iterations: {args.max_iterations}")
    else:
        print(f"   Train: {1-args.test_size:.0%}, Test: {args.test_size:.0%} (No validation)")
    
    if args.max_files:
        print(f"   Dataset limit: {args.max_files:,} files")
    else:
        print(f"   Dataset: Full dataset (300K+ files)")
    
    try:
        # Initialize ML engine
        print("\n[1/4] Initializing ML Engine...")
        engine = MLVulnerabilityEngine(cve_base_path="./cves")
        
        # Train model with validation
        print("\n[2/4] Training Model with Validation...")
        success = engine.train_model(
            max_files=args.max_files,
            use_validation=not args.no_validation,
            train_size=args.train_size,
            val_size=args.val_size,
            test_size=args.test_size,
            early_stopping_patience=args.patience,
            max_iterations=args.max_iterations
        )
        
        if not success:
            print("Training failed!")
            return
        
        # Model evaluation
        print("\n[3/4] Model Evaluation...")
        evaluation = engine.evaluate_model_comprehensive()
        
        if 'error' not in evaluation:
            display_evaluation_results(evaluation)
        else:
            print(f"Evaluation failed: {evaluation['error']}")
        
        # Plot training history
        if args.plot_history and not args.no_validation:
            print("\n[4/4] Plotting Training History...")
            try:
                plot_path = f"training_history_{len(engine.metadata.training_history['train_accuracy'])}iter.png"
                engine.plot_training_history(save_path=plot_path)
            except Exception as e:
                print(f"Warning: Plotting failed: {e}")
        
        # Test predictions
        print("\nTesting Predictions on Sample Vulnerabilities...")
        test_predictions(engine)
        
        print("\nTraining completed successfully!")
        print("Model saved in: ./trained_models/")
        
    except KeyboardInterrupt:
        print("\nTraining interrupted by user")
    except Exception as e:
        print(f"Training failed: {e}")
        traceback.print_exc()

def display_evaluation_results(evaluation: Dict[str, Any]) -> None:
    """
    Display model evaluation results in a structured format.
    
    Args:
        evaluation: Dictionary containing model evaluation metrics including
                   accuracy, precision, recall, F1-score, and training statistics
                   
    Returns:
        None
    """
    print("MODEL EVALUATION RESULTS")
    print("-" * 50)
    
    # Basic model information
    print(f"Model Type: {evaluation.get('model_type', 'Unknown')}")
    print(f"Model Version: {evaluation.get('model_version', 'Unknown')}")
    print(f"Training Samples: {evaluation.get('training_samples', 0):,}")
    
    if evaluation.get('validation_samples', 0) > 0:
        print(f"Validation Samples: {evaluation.get('validation_samples', 0):,}")
    
    print(f"Test Samples: {evaluation.get('test_samples', 0):,}")
    print(f"Feature Count: {evaluation.get('feature_count', 0):,}")
    
    # Performance metrics
    print("\nPERFORMANCE METRICS:")
    print(f"   Test Accuracy:  {evaluation.get('test_accuracy', 0):.3f}")
    print(f"   Test Precision: {evaluation.get('test_precision', 0):.3f}")
    print(f"   Test Recall:    {evaluation.get('test_recall', 0):.3f}")
    print(f"   Test F1-Score:  {evaluation.get('test_f1_score', 0):.3f}")
    
    if evaluation.get('best_val_accuracy'):
        print(f"   Best Val Accuracy: {evaluation.get('best_val_accuracy', 0):.3f}")
        print(f"   Best Iteration: {evaluation.get('best_iteration', 0) + 1}")
        print(f"   Total Iterations: {evaluation.get('total_iterations_trained', 0)}")
    
    # Training insights
    print("\nTRAINING INSIGHTS:")
    print(f"   Training Time: {evaluation.get('training_time_seconds', 0):.1f}s")
    
    if evaluation.get('overfitting_detected'):
        print("   Overfitting: DETECTED")
    else:
        print("   Overfitting: Not detected")
    
    # Convergence analysis
    convergence = evaluation.get('convergence_analysis', {})
    if convergence and convergence.get('status') != 'no_data':
        print("\nCONVERGENCE ANALYSIS:")
        print(f"   Status: {convergence.get('status', 'unknown').replace('_', ' ').title()}")
        print(f"   Analysis: {convergence.get('analysis', 'No analysis available')}")
        print(f"   Overfitting Risk: {convergence.get('overfitting_risk', 'unknown').title()}")
        
        if convergence.get('train_val_gap') is not None:
            gap = convergence.get('train_val_gap', 0)
            print(f"   Train-Val Gap: {gap:.3f}")
            
            if gap > 0.1:
                print("   WARNING: Large gap indicates potential overfitting")
            elif gap > 0.05:
                print("   CAUTION: Moderate gap - monitor for overfitting")
            else:
                print("   STATUS: Good generalization")

def test_predictions(engine: MLVulnerabilityEngine) -> None:
    """
    Test the trained model with sample vulnerability descriptions.
    
    Evaluates model performance on predefined test cases covering different
    vulnerability types and severity levels. Provides accuracy assessment
    for vulnerability classification predictions.
    
    Args:
        engine: Trained MLVulnerabilityEngine instance for prediction testing
        
    Returns:
        None
    """
    test_cases = [
        {
            'description': 'Buffer overflow vulnerability allows remote code execution through network service',
            'expected': 'critical'
        },
        {
            'description': 'SQL injection vulnerability in web application login form allows database access',
            'expected': 'high'
        },
        {
            'description': 'Cross-site scripting vulnerability in user input field allows script execution',
            'expected': 'medium'
        },
        {
            'description': 'Information disclosure vulnerability reveals server version in error messages',
            'expected': 'low'
        },
        {
            'description': 'Authentication bypass allows unauthorized administrator access to control panel',
            'expected': 'high'
        }
    ]
    
    print("SAMPLE PREDICTION TESTS:")
    print("-" * 60)
    
    correct_predictions = 0
    
    for i, test_case in enumerate(test_cases, 1):
        try:
            result = engine.predict_vulnerability(test_case['description'])
            predicted = result['predicted_severity']
            confidence = result['confidence']
            reliable = result['is_reliable']
            
            # Check if prediction matches expected (allowing for reasonable variations)
            severity_order = ['low', 'medium', 'high', 'critical']
            expected_idx = severity_order.index(test_case['expected'])
            predicted_idx = severity_order.index(predicted)
            
            # Consider prediction correct if within 1 severity level
            is_correct = abs(expected_idx - predicted_idx) <= 1
            if is_correct:
                correct_predictions += 1
            
            status = "CORRECT" if is_correct else "INCORRECT"
            reliability = "RELIABLE" if reliable else "UNCERTAIN"
            
            print(f"{i}. {test_case['description'][:50]}...")
            print(f"   Expected: {test_case['expected'].title():8} | "
                  f"Predicted: {predicted.title():8} | "
                  f"Confidence: {confidence:.3f} | "
                  f"{reliability} | {status}")
            
        except Exception as e:
            print(f"{i}. Prediction failed: {e}")
    
    accuracy = correct_predictions / len(test_cases)
    print(f"\nSample Test Accuracy: {accuracy:.1%} ({correct_predictions}/{len(test_cases)})")

if __name__ == "__main__":
    main()
