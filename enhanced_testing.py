#!/usr/bin/env python3
"""
Enhanced Testing Framework for Metamorphic Payload API
Provides comprehensive testing capabilities including payload validation,
performance testing, security testing, and API endpoint verification.
"""

import requests
import time
import hashlib
import threading
import statistics
import json
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple
import concurrent.futures
import subprocess
import re

class APITester:
    """Comprehensive API testing framework"""
    
    def __init__(self, base_url: str = "http://localhost:8080", api_key: str = "your_api_key_here"):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {'x-api-key': api_key}
        self.test_results = []
        self.performance_data = []
        
    def test_health_endpoint(self) -> Dict[str, Any]:
        """Test the health check endpoint"""
        print("Testing health endpoint...")
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            result = {
                'test': 'health_check',
                'status': 'pass' if response.status_code == 200 else 'fail',
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'response_data': response.json() if response.status_code == 200 else None
            }
        except Exception as e:
            result = {
                'test': 'health_check',
                'status': 'error',
                'error': str(e)
            }
        
        self.test_results.append(result)
        return result
    
    def test_authentication(self) -> Dict[str, Any]:
        """Test API key authentication"""
        print("Testing authentication...")
        
        # Test with valid API key
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/metamorphic/generate",
                headers=self.headers,
                timeout=30
            )
            valid_auth_result = {
                'test': 'valid_authentication',
                'status': 'pass' if response.status_code in [200, 201] else 'fail',
                'status_code': response.status_code
            }
        except Exception as e:
            valid_auth_result = {
                'test': 'valid_authentication',
                'status': 'error',
                'error': str(e)
            }
        
        # Test with invalid API key
        try:
            invalid_headers = {'x-api-key': 'invalid_key_123'}
            response = requests.post(
                f"{self.base_url}/api/v1/metamorphic/generate",
                headers=invalid_headers,
                timeout=10
            )
            invalid_auth_result = {
                'test': 'invalid_authentication',
                'status': 'pass' if response.status_code == 404 else 'fail',
                'status_code': response.status_code
            }
        except Exception as e:
            invalid_auth_result = {
                'test': 'invalid_authentication',
                'status': 'error',
                'error': str(e)
            }
        
        # Test with missing API key
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/metamorphic/generate",
                timeout=10
            )
            missing_auth_result = {
                'test': 'missing_authentication',
                'status': 'pass' if response.status_code == 404 else 'fail',
                'status_code': response.status_code
            }
        except Exception as e:
            missing_auth_result = {
                'test': 'missing_authentication',
                'status': 'error',
                'error': str(e)
            }
        
        results = [valid_auth_result, invalid_auth_result, missing_auth_result]
        self.test_results.extend(results)
        return results
    
    def test_payload_generation(self, num_tests: int = 5) -> List[Dict[str, Any]]:
        """Test payload generation with uniqueness verification"""
        print(f"Testing payload generation ({num_tests} iterations)...")
        
        payloads = []
        hashes = set()
        results = []
        
        for i in range(num_tests):
            try:
                start_time = time.time()
                response = requests.post(
                    f"{self.base_url}/api/v1/metamorphic/generate",
                    headers=self.headers,
                    timeout=60
                )
                end_time = time.time()
                
                if response.status_code == 200:
                    payload_content = response.text
                    payload_hash = hashlib.sha256(payload_content.encode()).hexdigest()
                    
                    # Check for uniqueness
                    is_unique = payload_hash not in hashes
                    hashes.add(payload_hash)
                    payloads.append(payload_content)
                    
                    # Analyze payload complexity
                    complexity_score = self._analyze_payload_complexity(payload_content)
                    
                    result = {
                        'test': f'payload_generation_{i+1}',
                        'status': 'pass',
                        'status_code': response.status_code,
                        'response_time': end_time - start_time,
                        'payload_hash': payload_hash,
                        'payload_size': len(payload_content),
                        'is_unique': is_unique,
                        'complexity_score': complexity_score,
                        'generation_time_header': response.headers.get('X-Generation-Time', 'N/A')
                    }
                    
                    self.performance_data.append({
                        'endpoint': 'generate',
                        'response_time': end_time - start_time,
                        'payload_size': len(payload_content),
                        'complexity_score': complexity_score
                    })
                    
                else:
                    result = {
                        'test': f'payload_generation_{i+1}',
                        'status': 'fail',
                        'status_code': response.status_code,
                        'response_time': end_time - start_time,
                        'error_message': response.text[:200] if response.text else 'No error message'
                    }
                
            except Exception as e:
                result = {
                    'test': f'payload_generation_{i+1}',
                    'status': 'error',
                    'error': str(e)
                }
            
            results.append(result)
            self.test_results.append(result)
            
            # Brief pause between requests
            time.sleep(0.1)
        
        # Calculate uniqueness statistics
        unique_count = len(hashes)
        uniqueness_rate = (unique_count / num_tests) * 100 if num_tests > 0 else 0
        
        summary = {
            'test': 'payload_uniqueness_summary',
            'total_generated': num_tests,
            'unique_payloads': unique_count,
            'uniqueness_rate': uniqueness_rate,
            'status': 'pass' if uniqueness_rate >= 95 else 'fail'
        }
        
        results.append(summary)
        self.test_results.append(summary)
        
        return results
    
    def test_download_endpoint(self, num_tests: int = 3) -> List[Dict[str, Any]]:
        """Test the download endpoint"""
        print(f"Testing download endpoint ({num_tests} iterations)...")
        
        results = []
        
        for i in range(num_tests):
            try:
                start_time = time.time()
                filename = f"test_payload_{i+1}.ps1"
                response = requests.get(
                    f"{self.base_url}/api/v1/metamorphic/download/{filename}",
                    headers=self.headers,
                    timeout=60
                )
                end_time = time.time()
                
                if response.status_code == 200:
                    # Verify it's a PowerShell file
                    content_type = response.headers.get('Content-Type', '')
                    is_ps1 = 'powershell' in content_type.lower() or filename.endswith('.ps1')
                    
                    # Check content
                    content = response.text if hasattr(response, 'text') else str(response.content)
                    has_powershell_content = any(keyword in content for keyword in 
                                               ['PowerShell', '$', 'function', 'param', 'try', 'catch'])
                    
                    result = {
                        'test': f'download_endpoint_{i+1}',
                        'status': 'pass' if is_ps1 and has_powershell_content else 'fail',
                        'status_code': response.status_code,
                        'response_time': end_time - start_time,
                        'content_type': content_type,
                        'content_size': len(content),
                        'is_ps1_format': is_ps1,
                        'has_powershell_content': has_powershell_content
                    }
                else:
                    result = {
                        'test': f'download_endpoint_{i+1}',
                        'status': 'fail',
                        'status_code': response.status_code,
                        'response_time': end_time - start_time,
                        'error_message': response.text[:200] if hasattr(response, 'text') else 'No error message'
                    }
                
            except Exception as e:
                result = {
                    'test': f'download_endpoint_{i+1}',
                    'status': 'error',
                    'error': str(e)
                }
            
            results.append(result)
            self.test_results.append(result)
            time.sleep(0.1)
        
        return results
    
    def test_rate_limiting(self, requests_per_minute: int = 15) -> Dict[str, Any]:
        """Test rate limiting functionality"""
        print("Testing rate limiting...")
        
        start_time = time.time()
        successful_requests = 0
        rate_limited_requests = 0
        
        # Send requests rapidly
        for i in range(requests_per_minute):
            try:
                response = requests.post(
                    f"{self.base_url}/api/v1/metamorphic/generate",
                    headers=self.headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    successful_requests += 1
                elif response.status_code == 429:
                    rate_limited_requests += 1
                    
            except Exception:
                pass
            
            # Very brief pause to simulate rapid requests
            time.sleep(0.1)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        result = {
            'test': 'rate_limiting',
            'status': 'pass' if rate_limited_requests > 0 else 'fail',
            'total_requests': requests_per_minute,
            'successful_requests': successful_requests,
            'rate_limited_requests': rate_limited_requests,
            'total_time_seconds': total_time,
            'requests_per_second': requests_per_minute / total_time if total_time > 0 else 0
        }
        
        self.test_results.append(result)
        return result
    
    def test_concurrent_requests(self, num_threads: int = 5, requests_per_thread: int = 3) -> Dict[str, Any]:
        """Test concurrent request handling"""
        print(f"Testing concurrent requests ({num_threads} threads, {requests_per_thread} requests each)...")
        
        def make_request(thread_id: int, request_id: int) -> Dict[str, Any]:
            try:
                start_time = time.time()
                response = requests.post(
                    f"{self.base_url}/api/v1/metamorphic/generate",
                    headers=self.headers,
                    timeout=30
                )
                end_time = time.time()
                
                return {
                    'thread_id': thread_id,
                    'request_id': request_id,
                    'status_code': response.status_code,
                    'response_time': end_time - start_time,
                    'success': response.status_code == 200
                }
            except Exception as e:
                return {
                    'thread_id': thread_id,
                    'request_id': request_id,
                    'error': str(e),
                    'success': False
                }
        
        start_time = time.time()
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            for thread_id in range(num_threads):
                for request_id in range(requests_per_thread):
                    future = executor.submit(make_request, thread_id, request_id)
                    futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        
        end_time = time.time()
        
        successful_requests = sum(1 for r in results if r.get('success', False))
        total_requests = len(results)
        response_times = [r.get('response_time', 0) for r in results if 'response_time' in r]
        
        result = {
            'test': 'concurrent_requests',
            'status': 'pass' if successful_requests >= total_requests * 0.8 else 'fail',
            'total_requests': total_requests,
            'successful_requests': successful_requests,
            'success_rate': (successful_requests / total_requests) * 100 if total_requests > 0 else 0,
            'total_time_seconds': end_time - start_time,
            'average_response_time': statistics.mean(response_times) if response_times else 0,
            'median_response_time': statistics.median(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0
        }
        
        self.test_results.append(result)
        return result
    
    def test_payload_validation(self, num_samples: int = 3) -> List[Dict[str, Any]]:
        """Validate generated payload structure and content"""
        print(f"Testing payload validation ({num_samples} samples)...")
        
        results = []
        
        for i in range(num_samples):
            try:
                response = requests.post(
                    f"{self.base_url}/api/v1/metamorphic/generate",
                    headers=self.headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    payload = response.text
                    validation_result = self._validate_payload_structure(payload)
                    
                    result = {
                        'test': f'payload_validation_{i+1}',
                        'status': 'pass' if validation_result['is_valid'] else 'fail',
                        'payload_size': len(payload),
                        'validation_details': validation_result
                    }
                else:
                    result = {
                        'test': f'payload_validation_{i+1}',
                        'status': 'fail',
                        'status_code': response.status_code,
                        'error': 'Failed to generate payload for validation'
                    }
                
            except Exception as e:
                result = {
                    'test': f'payload_validation_{i+1}',
                    'status': 'error',
                    'error': str(e)
                }
            
            results.append(result)
            self.test_results.append(result)
        
        return results
    
    def _analyze_payload_complexity(self, payload: str) -> int:
        """Analyze payload complexity based on various metrics"""
        score = 0
        
        # Count variables
        variables = len(re.findall(r'\$\w+', payload))
        score += variables * 2
        
        # Count functions
        functions = len(re.findall(r'function\s+\w+', payload))
        score += functions * 10
        
        # Count obfuscated strings
        obfuscated_strings = len(re.findall(r'\[System\.Text\.Encoding\]', payload))
        score += obfuscated_strings * 5
        
        # Count try-catch blocks
        try_blocks = payload.count('try {')
        score += try_blocks * 8
        
        # Count unique character sets
        unique_chars = len(set(payload))
        score += unique_chars
        
        # Entropy calculation (simplified)
        if payload:
            char_freq = {}
            for char in payload:
                char_freq[char] = char_freq.get(char, 0) + 1
            
            entropy = 0
            total_chars = len(payload)
            for freq in char_freq.values():
                prob = freq / total_chars
                if prob > 0:
                    entropy -= prob * math.log2(prob)
            
            score += int(entropy * 10)
        
        return score
    
    def _validate_payload_structure(self, payload: str) -> Dict[str, Any]:
        """Validate payload structure and content"""
        validation = {
            'is_valid': True,
            'issues': [],
            'features': {}
        }
        
        # Check for PowerShell syntax
        if not any(keyword in payload for keyword in ['$', 'function', 'param']):
            validation['is_valid'] = False
            validation['issues'].append('Missing PowerShell syntax indicators')
        
        # Check for AMSI bypass
        amsi_indicators = ['AmsiUtils', 'amsiInitFailed', 'Ref].Assembly']
        has_amsi_bypass = any(indicator in payload for indicator in amsi_indicators)
        validation['features']['has_amsi_bypass'] = has_amsi_bypass
        
        # Check for obfuscation
        obfuscation_indicators = [
            '[System.Text.Encoding]',
            '[Convert]::FromBase64String',
            '[char]',
            'ForEach-Object'
        ]
        obfuscation_count = sum(1 for indicator in obfuscation_indicators if indicator in payload)
        validation['features']['obfuscation_techniques'] = obfuscation_count
        
        # Check for error handling
        has_error_handling = 'try {' in payload and 'catch {' in payload
        validation['features']['has_error_handling'] = has_error_handling
        
        # Check for junk code (comments, unused variables)
        junk_indicators = payload.count('#') + len(re.findall(r'\$\w+.*=.*[\'"].*[\'"]', payload))
        validation['features']['junk_code_elements'] = junk_indicators
        
        # Minimum complexity check
        if obfuscation_count < 2:
            validation['issues'].append('Insufficient obfuscation techniques')
        
        if not has_error_handling:
            validation['issues'].append('Missing error handling')
        
        # Final validation
        if validation['issues']:
            validation['is_valid'] = False
        
        return validation
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all test suites"""
        print("=" * 60)
        print("METAMORPHIC PAYLOAD API - COMPREHENSIVE TEST SUITE")
        print("=" * 60)
        
        start_time = time.time()
        
        # Run all test suites
        self.test_health_endpoint()
        self.test_authentication()
        self.test_payload_generation(num_tests=5)
        self.test_download_endpoint(num_tests=3)
        self.test_payload_validation(num_samples=3)
        self.test_rate_limiting(requests_per_minute=12)
        self.test_concurrent_requests(num_threads=3, requests_per_thread=2)
        
        end_time = time.time()
        
        # Calculate summary statistics
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result.get('status') == 'pass')
        failed_tests = sum(1 for result in self.test_results if result.get('status') == 'fail')
        error_tests = sum(1 for result in self.test_results if result.get('status') == 'error')
        
        summary = {
            'test_execution_time': end_time - start_time,
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'error_tests': error_tests,
            'success_rate': (passed_tests / total_tests) * 100 if total_tests > 0 else 0,
            'performance_data': self.performance_data,
            'detailed_results': self.test_results
        }
        
        return summary
    
    def generate_report(self, summary: Dict[str, Any], output_file: str = None) -> str:
        """Generate a comprehensive test report"""
        report = []
        report.append("=" * 80)
        report.append("METAMORPHIC PAYLOAD API - TEST REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Test Execution Time: {summary['test_execution_time']:.2f} seconds")
        report.append("")
        
        # Summary
        report.append("SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Tests: {summary['total_tests']}")
        report.append(f"Passed: {summary['passed_tests']}")
        report.append(f"Failed: {summary['failed_tests']}")
        report.append(f"Errors: {summary['error_tests']}")
        report.append(f"Success Rate: {summary['success_rate']:.1f}%")
        report.append("")
        
        # Performance Analysis
        if summary['performance_data']:
            report.append("PERFORMANCE ANALYSIS")
            report.append("-" * 40)
            response_times = [d['response_time'] for d in summary['performance_data']]
            payload_sizes = [d['payload_size'] for d in summary['performance_data']]
            
            report.append(f"Average Response Time: {statistics.mean(response_times):.3f}s")
            report.append(f"Median Response Time: {statistics.median(response_times):.3f}s")
            report.append(f"Max Response Time: {max(response_times):.3f}s")
            report.append(f"Average Payload Size: {statistics.mean(payload_sizes):.0f} bytes")
            report.append(f"Max Payload Size: {max(payload_sizes)} bytes")
            report.append("")
        
        # Detailed Results
        report.append("DETAILED TEST RESULTS")
        report.append("-" * 40)
        for result in summary['detailed_results']:
            test_name = result.get('test', 'Unknown Test')
            status = result.get('status', 'Unknown').upper()
            
            report.append(f"{test_name}: {status}")
            
            if status == 'FAIL' and 'error' in result:
                report.append(f"  Error: {result['error']}")
            elif status == 'FAIL' and 'issues' in result.get('validation_details', {}):
                issues = result['validation_details']['issues']
                report.append(f"  Issues: {', '.join(issues)}")
            
            if 'response_time' in result:
                report.append(f"  Response Time: {result['response_time']:.3f}s")
            
            report.append("")
        
        report_text = "\n".join(report)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"Test report saved to: {output_file}")
        
        return report_text

def main():
    parser = argparse.ArgumentParser(description='Enhanced Metamorphic Payload API Tester')
    parser.add_argument('--url', default='http://localhost:8080', help='API base URL')
    parser.add_argument('--api-key', default='your_api_key_here', help='API key for authentication')
    parser.add_argument('--output', help='Output file for test report')
    parser.add_argument('--quick', action='store_true', help='Run quick test suite')
    
    args = parser.parse_args()
    
    tester = APITester(base_url=args.url, api_key=args.api_key)
    
    if args.quick:
        # Quick test suite
        print("Running quick test suite...")
        tester.test_health_endpoint()
        tester.test_payload_generation(num_tests=2)
        tester.test_authentication()
    else:
        # Full test suite
        summary = tester.run_all_tests()
        
        # Generate and display report
        report = tester.generate_report(summary, args.output)
        print("\n" + report)
        
        # Exit with appropriate code
        if summary['success_rate'] < 80:
            print("\nWARNING: Test success rate below 80%!")
            sys.exit(1)
        else:
            print(f"\nAll tests completed successfully! Success rate: {summary['success_rate']:.1f}%")
            sys.exit(0)

if __name__ == "__main__":
    main()
