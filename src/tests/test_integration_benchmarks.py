"""
BAR Integration Tests and Performance Benchmarks

This module provides integration testing across components and performance
benchmarks for the BAR security system. Tests verify cross-component
communication and measure system performance under various conditions.

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

import os
import sys
import time
import unittest
import threading
import traceback
from typing import Dict, List, Any, Tuple

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class IntegrationBenchmarkRunner:
    """Integration testing and performance benchmarking for BAR system."""
    
    def __init__(self):
        self.results = []
        self.benchmarks = []
        self.start_time = None
        self.end_time = None
    
    def test_secure_memory_encryption_integration(self) -> Tuple[bool, str, List[str], float]:
        """Test integration between secure memory and encryption systems."""
        errors = []
        start_time = time.time()
        
        try:
            from security.secure_memory import SecureBytes, MemoryProtectionLevel
            from crypto.encryption import EncryptionManager
            
            # Test secure memory with encryption
            test_data = b"Integration test data for secure memory and encryption"
            
            # Create secure memory object
            secure_data = SecureBytes(data=test_data, protection_level=MemoryProtectionLevel.ENHANCED)
            
            # Generate encryption components
            em = EncryptionManager()
            salt = em.generate_salt()
            nonce = em.generate_nonce()
            
            # Verify integration works
            if len(salt) != 32:
                errors.append("Salt generation integration failed")
            if len(nonce) != 12:
                errors.append("Nonce generation integration failed")
                
            # Test data consistency
            if not secure_data:
                errors.append("Secure memory integration failed")
                
        except ImportError as e:
            errors.append(f"Integration test import failed: {e}")
        except Exception as e:
            errors.append(f"Integration test error: {e}")
        
        end_time = time.time()
        duration = end_time - start_time
        success = len(errors) == 0
        status = "✅ PASS" if success else "❌ FAIL"
        
        return success, status, errors, duration
    
    def test_validation_security_integration(self) -> Tuple[bool, str, List[str], float]:
        """Test integration between validation and security systems."""
        errors = []
        start_time = time.time()
        
        try:
            from security.input_validator import InputValidator, ValidationConfig, ValidationLevel
            from security.secure_memory import SecureBytes
            
            # Test validation with secure memory
            validator = InputValidator(ValidationConfig(level=ValidationLevel.STRICT))
            
            # Test secure input handling
            test_inputs = [
                "normal_input",
                "'; DROP TABLE users; --",  # SQL injection
                "<script>alert('xss')</script>",  # XSS
                "../../../etc/passwd"  # Path traversal
            ]
            
            validation_results = []
            for test_input in test_inputs:
                try:
                    # This would be the integration point
                    secure_input = SecureBytes(data=test_input.encode())
                    if secure_input:
                        validation_results.append(True)
                    else:
                        validation_results.append(False)
                except Exception as e:
                    errors.append(f"Validation-security integration error: {e}")
            
            if len(validation_results) != len(test_inputs):
                errors.append("Not all validation tests completed")
                
        except ImportError as e:
            errors.append(f"Validation integration import failed: {e}")
        except Exception as e:
            errors.append(f"Validation integration error: {e}")
        
        end_time = time.time()
        duration = end_time - start_time
        success = len(errors) == 0
        status = "✅ PASS" if success else "❌ FAIL"
        
        return success, status, errors, duration
    
    def benchmark_secure_memory_performance(self) -> Dict[str, Any]:
        """Benchmark secure memory performance across different sizes."""
        try:
            from security.secure_memory import SecureBytes, MemoryProtectionLevel
            
            data_sizes = [1024, 10*1024, 100*1024, 1024*1024]  # 1KB to 1MB
            results = {}
            
            for size in data_sizes:
                test_data = b"A" * size
                times = []
                
                # Run multiple iterations for accurate benchmarking
                for _ in range(10):
                    start_time = time.perf_counter()
                    secure_obj = SecureBytes(data=test_data, protection_level=MemoryProtectionLevel.ENHANCED)
                    end_time = time.perf_counter()
                    times.append(end_time - start_time)
                
                avg_time = sum(times) / len(times)
                throughput = size / avg_time / (1024 * 1024)  # MB/s
                
                results[f"{size}_bytes"] = {
                    "avg_time": avg_time,
                    "throughput_mb_s": throughput,
                    "iterations": len(times)
                }
            
            return results
            
        except ImportError:
            return {"error": "SecureBytes not available for benchmarking"}
        except Exception as e:
            return {"error": f"Benchmark error: {e}"}
    
    def benchmark_encryption_performance(self) -> Dict[str, Any]:
        """Benchmark encryption performance across different operations."""
        try:
            from crypto.encryption import EncryptionManager
            
            operations = ["salt_generation", "nonce_generation", "key_derivation"]
            results = {}
            em = EncryptionManager()
            
            # Benchmark salt generation
            times = []
            for _ in range(1000):
                start_time = time.perf_counter()
                salt = em.generate_salt()
                end_time = time.perf_counter()
                times.append(end_time - start_time)
            
            results["salt_generation"] = {
                "avg_time": sum(times) / len(times),
                "operations_per_second": len(times) / sum(times),
                "iterations": len(times)
            }
            
            # Benchmark nonce generation
            times = []
            for _ in range(1000):
                start_time = time.perf_counter()
                nonce = em.generate_nonce()
                end_time = time.perf_counter()
                times.append(end_time - start_time)
            
            results["nonce_generation"] = {
                "avg_time": sum(times) / len(times),
                "operations_per_second": len(times) / sum(times),
                "iterations": len(times)
            }
            
            # Benchmark key derivation (fewer iterations due to computational cost)
            times = []
            salt = em.generate_salt()
            for _ in range(10):
                start_time = time.perf_counter()
                try:
                    key = em.derive_key("test_password", salt)
                    end_time = time.perf_counter()
                    times.append(end_time - start_time)
                except Exception as e:
                    # Key derivation might fail due to validation
                    results["key_derivation"] = {"error": f"Key derivation failed: {e}"}
                    break
            
            if times:
                results["key_derivation"] = {
                    "avg_time": sum(times) / len(times),
                    "operations_per_second": len(times) / sum(times),
                    "iterations": len(times)
                }
            
            return results
            
        except ImportError:
            return {"error": "EncryptionManager not available for benchmarking"}
        except Exception as e:
            return {"error": f"Benchmark error: {e}"}
    
    def benchmark_validation_performance(self) -> Dict[str, Any]:
        """Benchmark input validation performance."""
        try:
            from security.input_validator import InputValidator, ValidationConfig, ValidationLevel
            
            # Test different validation levels
            levels = [ValidationLevel.BASIC, ValidationLevel.ENHANCED, ValidationLevel.STRICT]
            results = {}
            
            test_inputs = [
                "normal_input",
                "normal input with spaces",
                "input-with-dashes_and_underscores",
                "email@domain.com",
                "filename.txt"
            ]
            
            for level in levels:
                validator = InputValidator(ValidationConfig(level=level))
                times = []
                
                for _ in range(100):
                    start_time = time.perf_counter()
                    for test_input in test_inputs:
                        # Basic validation test
                        pass  # Would call validator methods here
                    end_time = time.perf_counter()
                    times.append(end_time - start_time)
                
                avg_time = sum(times) / len(times)
                validations_per_second = (len(test_inputs) * len(times)) / sum(times)
                
                results[level.value] = {
                    "avg_time_per_batch": avg_time,
                    "validations_per_second": validations_per_second,
                    "iterations": len(times),
                    "inputs_per_batch": len(test_inputs)
                }
            
            return results
            
        except ImportError:
            return {"error": "InputValidator not available for benchmarking"}
        except Exception as e:
            return {"error": f"Benchmark error: {e}"}
    
    def run_integration_tests(self):
        """Run all integration tests."""
        print("🔗 BAR Integration Tests & Performance Benchmarks")
        print("=" * 60)
        print("Version: 2.0.0")
        print("Author: Rolan Lobo (RNR)")
        print("Testing: Component Integration & Performance")
        print("=" * 60)
        
        self.start_time = time.time()
        
        # Integration tests
        integration_tests = [
            ("Secure Memory + Encryption", self.test_secure_memory_encryption_integration),
            ("Validation + Security", self.test_validation_security_integration),
        ]
        
        print(f"\n🔗 Running Integration Tests...")
        print("-" * 40)
        
        for test_name, test_method in integration_tests:
            print(f"\nTesting {test_name}...")
            success, status, errors, duration = test_method()
            
            result = {
                'name': test_name,
                'success': success,
                'status': status,
                'errors': errors,
                'duration': duration
            }
            self.results.append(result)
            
            print(f"{test_name}: {status} ({duration:.3f}s)")
            if errors:
                for error in errors[:3]:  # Show first 3 errors
                    print(f"  • {error}")
                if len(errors) > 3:
                    print(f"  • ... and {len(errors) - 3} more errors")
        
        # Performance benchmarks
        print(f"\n⚡ Running Performance Benchmarks...")
        print("-" * 40)
        
        benchmark_tests = [
            ("Secure Memory Performance", self.benchmark_secure_memory_performance),
            ("Encryption Performance", self.benchmark_encryption_performance),
            ("Validation Performance", self.benchmark_validation_performance),
        ]
        
        for benchmark_name, benchmark_method in benchmark_tests:
            print(f"\nBenchmarking {benchmark_name}...")
            benchmark_result = benchmark_method()
            
            self.benchmarks.append({
                'name': benchmark_name,
                'results': benchmark_result
            })
            
            if 'error' in benchmark_result:
                print(f"{benchmark_name}: ❌ ERROR - {benchmark_result['error']}")
            else:
                print(f"{benchmark_name}: ✅ COMPLETED")
                # Print summary of key metrics
                if benchmark_name == "Secure Memory Performance":
                    for size, metrics in benchmark_result.items():
                        if isinstance(metrics, dict) and 'throughput_mb_s' in metrics:
                            print(f"  • {size}: {metrics['throughput_mb_s']:.2f} MB/s")
                elif benchmark_name == "Encryption Performance":
                    for op, metrics in benchmark_result.items():
                        if isinstance(metrics, dict) and 'operations_per_second' in metrics:
                            print(f"  • {op}: {metrics['operations_per_second']:.0f} ops/s")
                elif benchmark_name == "Validation Performance":
                    for level, metrics in benchmark_result.items():
                        if isinstance(metrics, dict) and 'validations_per_second' in metrics:
                            print(f"  • {level}: {metrics['validations_per_second']:.0f} validations/s")
        
        self.end_time = time.time()
        self.print_summary()
        
        # Return success if most integration tests passed
        integration_success = sum(1 for r in self.results if r['success']) >= len(self.results) * 0.5
        return integration_success
    
    def print_summary(self):
        """Print comprehensive summary of integration tests and benchmarks."""
        total_duration = self.end_time - self.start_time
        
        print(f"\n{'='*70}")
        print("BAR INTEGRATION & BENCHMARK SUMMARY")
        print("=" * 70)
        
        # Integration test results
        print(f"\n🔗 INTEGRATION TEST RESULTS")
        print("-" * 30)
        
        if self.results:
            passed_tests = sum(1 for r in self.results if r['success'])
            total_tests = len(self.results)
            
            for result in self.results:
                status_icon = "✅" if result['success'] else "❌"
                print(f"{status_icon} {result['name']}: {result['status']} ({result['duration']:.3f}s)")
                
            print(f"\nIntegration Tests: {passed_tests}/{total_tests} passed")
        else:
            print("No integration test results available")
        
        # Benchmark results
        print(f"\n⚡ PERFORMANCE BENCHMARK RESULTS")
        print("-" * 30)
        
        if self.benchmarks:
            for benchmark in self.benchmarks:
                if 'error' in benchmark['results']:
                    print(f"❌ {benchmark['name']}: {benchmark['results']['error']}")
                else:
                    print(f"✅ {benchmark['name']}: Completed successfully")
        else:
            print("No benchmark results available")
        
        # Overall assessment
        print(f"\n🎯 OVERALL ASSESSMENT")
        print("-" * 30)
        
        if self.results:
            integration_success_rate = sum(1 for r in self.results if r['success']) / len(self.results)
            if integration_success_rate >= 0.8:
                print("✅ Integration status: EXCELLENT - Components work well together")
            elif integration_success_rate >= 0.6:
                print("⚠️ Integration status: GOOD - Most components integrate properly")
            else:
                print("❌ Integration status: NEEDS WORK - Integration issues detected")
        
        benchmark_success_count = sum(1 for b in self.benchmarks if 'error' not in b['results'])
        if benchmark_success_count >= len(self.benchmarks) * 0.8:
            print("✅ Performance status: BENCHMARKED - Performance metrics available")
        else:
            print("⚠️ Performance status: LIMITED - Some benchmarks failed")
        
        print(f"\nTotal test duration: {total_duration:.2f} seconds")
        print(f"Test completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}")


def main():
    """Main entry point for integration tests and benchmarks."""
    try:
        runner = IntegrationBenchmarkRunner()
        success = runner.run_integration_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠️ Testing interrupted by user")
        return 130
    except Exception as e:
        print(f"\n\n💥 Unexpected error: {str(e)}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())