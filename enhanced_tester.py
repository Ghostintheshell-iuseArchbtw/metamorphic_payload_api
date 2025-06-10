#!/usr/bin/env python3
"""
Enhanced Testing Framework for Metamorphic Payload API
Provides comprehensive testing of API functionality, security, and performance
"""

import requests
import time
import hashlib
import json
import threading
import statistics
from typing import List, Dict, Any, Optional
import argparse
import sys
from pathlib import Path
import concurrent.futures
from dataclasses import dataclass
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_results.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    """Test result data structure"""
    test_name: str
    success: bool
    duration: float
    response_code: int
    payload_hash: Optional[str] = None
    payload_size: Optional[int] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class MetamorphicAPITester:
    """Comprehensive tester for the Metamorphic Payload API"""
    
    def __init__(self, base_url: str = "http://localhost:8080", api_key: str = "your_api_key_here"):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'x-api-key': self.api_key,
            'User-Agent': 'MetamorphicAPI-Tester/2.0'
        })
        self.results: List[TestResult] = []
        
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with proper error handling"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.request(method, url, timeout=30, **kwargs)
            return response
        except requests.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise
    
    def _calculate_hash(self, content: str) -> str:
        """Calculate SHA-256 hash of content"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def test_health_check(self) -> TestResult:
        """Test health check endpoint"""
        start_time = time.time()
        try:
            # Health check shouldn't require API key
            response = requests.get(f"{self.base_url}/health", timeout=10)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                return TestResult(
                    test_name="health_check",
                    success=True,
                    duration=duration,
                    response_code=200,
                    metadata=data
                )
            else:
                return TestResult(
                    test_name="health_check",
                    success=False,
                    duration=duration,
                    response_code=response.status_code,
                    error_message=f"Unexpected status code: {response.status_code}"
                )
        except Exception as e:
            duration = time.time() - start_time
            return TestResult(
                test_name="health_check",
                success=False,
                duration=duration,
                response_code=0,
                error_message=str(e)
            )
    
    def test_authentication(self) -> List[TestResult]:
        """Test authentication mechanisms"""
        results = []
        
        # Test 1: Valid API key
        start_time = time.time()
        try:
            response = self._make_request('POST', '/api/v1/metamorphic/generate')
            duration = time.time() - start_time
            
            success = response.status_code in [200, 201]
            results.append(TestResult(
                test_name="auth_valid_key",
                success=success,
                duration=duration,
                response_code=response.status_code,
                payload_hash=self._calculate_hash(response.text) if success else None,
                payload_size=len(response.content) if success else None
            ))
        except Exception as e:
            duration = time.time() - start_time
            results.append(TestResult(
                test_name="auth_valid_key",
                success=False,
                duration=duration,
                response_code=0,
                error_message=str(e)
            ))
        
        # Test 2: Invalid API key
        start_time = time.time()
        try:
            invalid_session = requests.Session()
            invalid_session.headers.update({'x-api-key': 'invalid_key_12345'})
            response = invalid_session.post(f"{self.base_url}/api/v1/metamorphic/generate", timeout=10)
            duration = time.time() - start_time
            
            # Should return 404 to hide endpoint existence
            success = response.status_code == 404
            results.append(TestResult(
                test_name="auth_invalid_key",
                success=success,
                duration=duration,
                response_code=response.status_code,
                error_message="Expected 404 for invalid key" if not success else None
            ))
        except Exception as e:
            duration = time.time() - start_time
            results.append(TestResult(
                test_name="auth_invalid_key",
                success=False,
                duration=duration,
                response_code=0,
                error_message=str(e)
            ))
        
        # Test 3: No API key
        start_time = time.time()
        try:
            response = requests.post(f"{self.base_url}/api/v1/metamorphic/generate", timeout=10)
            duration = time.time() - start_time
            
            # Should return 404 to hide endpoint existence
            success = response.status_code == 404
            results.append(TestResult(
                test_name="auth_no_key",
                success=success,
                duration=duration,
                response_code=response.status_code,
                error_message="Expected 404 for no key" if not success else None
            ))
        except Exception as e:
            duration = time.time() - start_time
            results.append(TestResult(
                test_name="auth_no_key",
                success=False,
                duration=duration,
                response_code=0,
                error_message=str(e)
            ))
        
        return results
    
    def test_payload_generation(self, num_tests: int = 10) -> List[TestResult]:
        """Test payload generation with uniqueness verification"""
        results = []
        generated_hashes = set()
        
        for i in range(num_tests):
            start_time = time.time()
            try:
                response = self._make_request('POST', '/api/v1/metamorphic/generate')
                duration = time.time() - start_time
                
                if response.status_code == 200:
                    content = response.text
                    payload_hash = self._calculate_hash(content)
                    
                    # Check uniqueness
                    is_unique = payload_hash not in generated_hashes
                    generated_hashes.add(payload_hash)
                    
                    # Validate PowerShell syntax (basic check)
                    is_valid_ps = self._validate_powershell_syntax(content)
                    
                    success = is_unique and is_valid_ps
                    
                    results.append(TestResult(
                        test_name=f"payload_generation_{i+1}",
                        success=success,
                        duration=duration,
                        response_code=200,
                        payload_hash=payload_hash,
                        payload_size=len(content),
                        error_message=None if success else "Duplicate hash or invalid PowerShell" if not is_unique else "Invalid PowerShell syntax",
                        metadata={
                            'is_unique': is_unique,
                            'is_valid_ps': is_valid_ps,
                            'complexity_score': self._calculate_complexity_score(content)
                        }
                    ))
                else:
                    results.append(TestResult(
                        test_name=f"payload_generation_{i+1}",
                        success=False,
                        duration=duration,
                        response_code=response.status_code,
                        error_message=f"HTTP {response.status_code}: {response.text[:100]}"
                    ))
            except Exception as e:
                duration = time.time() - start_time
                results.append(TestResult(
                    test_name=f"payload_generation_{i+1}",
                    success=False,
                    duration=duration,
                    response_code=0,
                    error_message=str(e)
                ))
        
        return results
    
    def test_concurrent_generation(self, num_concurrent: int = 5, requests_per_thread: int = 3) -> List[TestResult]:
        """Test concurrent payload generation"""
        results = []
        
        def generate_payload_thread(thread_id: int) -> List[TestResult]:
            thread_results = []
            for i in range(requests_per_thread):
                start_time = time.time()
                try:
                    response = self._make_request('POST', '/api/v1/metamorphic/generate')
                    duration = time.time() - start_time
                    
                    if response.status_code == 200:
                        payload_hash = self._calculate_hash(response.text)
                        thread_results.append(TestResult(
                            test_name=f"concurrent_gen_t{thread_id}_r{i+1}",
                            success=True,
                            duration=duration,
                            response_code=200,
                            payload_hash=payload_hash,
                            payload_size=len(response.content)
                        ))
                    else:
                        thread_results.append(TestResult(
                            test_name=f"concurrent_gen_t{thread_id}_r{i+1}",
                            success=False,
                            duration=duration,
                            response_code=response.status_code,
                            error_message=response.text[:100]
                        ))
                except Exception as e:
                    duration = time.time() - start_time
                    thread_results.append(TestResult(
                        test_name=f"concurrent_gen_t{thread_id}_r{i+1}",
                        success=False,
                        duration=duration,
                        response_code=0,
                        error_message=str(e)
                    ))
            return thread_results
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            futures = [executor.submit(generate_payload_thread, i) for i in range(num_concurrent)]
            for future in concurrent.futures.as_completed(futures):
                results.extend(future.result())
        
        return results
    
    def test_rate_limiting(self) -> TestResult:
        """Test rate limiting functionality"""
        start_time = time.time()
        
        # Make rapid requests to trigger rate limiting
        responses = []
        for i in range(15):  # Assuming rate limit is 10 per minute
            try:
                response = self._make_request('POST', '/api/v1/metamorphic/generate')
                responses.append(response.status_code)
            except Exception:
                responses.append(0)
        
        duration = time.time() - start_time
        
        # Check if we got rate limited (429 status code)
        rate_limited = 429 in responses
        
        return TestResult(
            test_name="rate_limiting",
            success=rate_limited,
            duration=duration,
            response_code=429 if rate_limited else responses[-1],
            error_message="Rate limiting not triggered" if not rate_limited else None,
            metadata={'response_codes': responses}
        )
    
    def test_download_endpoint(self) -> TestResult:
        """Test download endpoint functionality"""
        start_time = time.time()
        try:
            response = self._make_request('GET', '/api/v1/metamorphic/download/test_payload.ps1')
            duration = time.time() - start_time
            
            if response.status_code == 200:
                # Check if it's a valid PowerShell file
                content_type = response.headers.get('content-type', '')
                is_ps_file = 'powershell' in content_type.lower() or response.text.strip().startswith('#') or '$' in response.text
                
                return TestResult(
                    test_name="download_endpoint",
                    success=is_ps_file,
                    duration=duration,
                    response_code=200,
                    payload_hash=self._calculate_hash(response.text),
                    payload_size=len(response.content),
                    error_message=None if is_ps_file else "Not a valid PowerShell file"
                )
            else:
                return TestResult(
                    test_name="download_endpoint",
                    success=False,
                    duration=duration,
                    response_code=response.status_code,
                    error_message=f"HTTP {response.status_code}"
                )
        except Exception as e:
            duration = time.time() - start_time
            return TestResult(
                test_name="download_endpoint",
                success=False,
                duration=duration,
                response_code=0,
                error_message=str(e)
            )
    
    def test_metrics_endpoint(self) -> TestResult:
        """Test metrics endpoint functionality"""
        start_time = time.time()
        try:
            response = self._make_request('GET', '/metrics')
            duration = time.time() - start_time
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    has_required_fields = all(key in data for key in ['generation_stats', 'config', 'system'])
                    
                    return TestResult(
                        test_name="metrics_endpoint",
                        success=has_required_fields,
                        duration=duration,
                        response_code=200,
                        metadata=data,
                        error_message=None if has_required_fields else "Missing required metrics fields"
                    )
                except json.JSONDecodeError:
                    return TestResult(
                        test_name="metrics_endpoint",
                        success=False,
                        duration=duration,
                        response_code=200,
                        error_message="Invalid JSON response"
                    )
            else:
                return TestResult(
                    test_name="metrics_endpoint",
                    success=False,
                    duration=duration,
                    response_code=response.status_code,
                    error_message=f"HTTP {response.status_code}"
                )
        except Exception as e:
            duration = time.time() - start_time
            return TestResult(
                test_name="metrics_endpoint",
                success=False,
                duration=duration,
                response_code=0,
                error_message=str(e)
            )
    
    def _validate_powershell_syntax(self, content: str) -> bool:
        """Basic PowerShell syntax validation"""
        # Check for basic PowerShell indicators
        ps_indicators = ['$', 'function', 'param', 'try', 'catch', 'if', 'foreach']
        has_indicators = any(indicator in content.lower() for indicator in ps_indicators)
        
        # Check for balanced braces
        open_braces = content.count('{')
        close_braces = content.count('}')
        balanced_braces = open_braces == close_braces
        
        # Check for common PowerShell cmdlets or .NET classes
        ps_elements = ['[System.', 'New-Object', 'Get-', 'Set-', 'Invoke-']
        has_ps_elements = any(element in content for element in ps_elements)
        
        return has_indicators and balanced_braces and has_ps_elements
    
    def _calculate_complexity_score(self, content: str) -> int:
        """Calculate complexity score for payload"""
        score = 0
        score += len(re.findall(r'\$\w+', content)) * 2  # Variables
        score += len(re.findall(r'function\s+\w+', content)) * 5  # Functions
        score += len(re.findall(r'\[.*?\]', content)) * 3  # Type casts
        score += len(re.findall(r'-\w+', content))  # Parameters
        score += content.count('try') * 10  # Error handling
        score += content.count('catch') * 10  # Error handling
        return score
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run comprehensive test suite"""
        logger.info("Starting comprehensive test suite...")
        
        all_results = []
        
        # Test 1: Health Check
        logger.info("Testing health check endpoint...")
        health_result = self.test_health_check()
        all_results.append(health_result)
        
        # Test 2: Authentication
        logger.info("Testing authentication mechanisms...")
        auth_results = self.test_authentication()
        all_results.extend(auth_results)
        
        # Test 3: Payload Generation
        logger.info("Testing payload generation (10 payloads)...")
        generation_results = self.test_payload_generation(10)
        all_results.extend(generation_results)
        
        # Test 4: Concurrent Generation
        logger.info("Testing concurrent payload generation...")
        concurrent_results = self.test_concurrent_generation(5, 3)
        all_results.extend(concurrent_results)
        
        # Test 5: Rate Limiting
        logger.info("Testing rate limiting...")
        rate_limit_result = self.test_rate_limiting()
        all_results.append(rate_limit_result)
        
        # Test 6: Download Endpoint
        logger.info("Testing download endpoint...")
        download_result = self.test_download_endpoint()
        all_results.append(download_result)
        
        # Test 7: Metrics Endpoint
        logger.info("Testing metrics endpoint...")
        metrics_result = self.test_metrics_endpoint()
        all_results.append(metrics_result)
        
        self.results = all_results
        
        # Calculate summary statistics
        summary = self._generate_summary()
        
        logger.info(f"Test suite completed. {summary['total_tests']} tests run, {summary['passed']} passed, {summary['failed']} failed")
        
        return summary
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate test summary statistics"""
        total_tests = len(self.results)
        passed = sum(1 for r in self.results if r.success)
        failed = total_tests - passed
        
        durations = [r.duration for r in self.results if r.duration > 0]
        
        unique_hashes = set()
        payload_sizes = []
        complexity_scores = []
        
        for result in self.results:
            if result.payload_hash:
                unique_hashes.add(result.payload_hash)
            if result.payload_size:
                payload_sizes.append(result.payload_size)
            if result.metadata and 'complexity_score' in result.metadata:
                complexity_scores.append(result.metadata['complexity_score'])
        
        summary = {
            'total_tests': total_tests,
            'passed': passed,
            'failed': failed,
            'success_rate': (passed / total_tests * 100) if total_tests > 0 else 0,
            'average_duration': statistics.mean(durations) if durations else 0,
            'median_duration': statistics.median(durations) if durations else 0,
            'unique_payloads': len(unique_hashes),
            'average_payload_size': statistics.mean(payload_sizes) if payload_sizes else 0,
            'average_complexity': statistics.mean(complexity_scores) if complexity_scores else 0,
            'failed_tests': [r.test_name for r in self.results if not r.success]
        }
        
        return summary
    
    def save_results(self, filename: str = None):
        """Save test results to JSON file"""
        if filename is None:
            filename = f"test_results_{int(time.time())}.json"
        
        results_data = {
            'timestamp': time.time(),
            'summary': self._generate_summary(),
            'detailed_results': [
                {
                    'test_name': r.test_name,
                    'success': r.success,
                    'duration': r.duration,
                    'response_code': r.response_code,
                    'payload_hash': r.payload_hash,
                    'payload_size': r.payload_size,
                    'error_message': r.error_message,
                    'metadata': r.metadata
                }
                for r in self.results
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        logger.info(f"Test results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Enhanced Metamorphic API Tester')
    parser.add_argument('--url', default='http://localhost:8080', help='Base URL of the API')
    parser.add_argument('--api-key', default='your_api_key_here', help='API key for authentication')
    parser.add_argument('--output', help='Output file for results (JSON)')
    parser.add_argument('--concurrent', type=int, default=5, help='Number of concurrent threads for concurrent tests')
    parser.add_argument('--payloads', type=int, default=10, help='Number of payloads to generate for uniqueness testing')
    
    args = parser.parse_args()
    
    tester = MetamorphicAPITester(args.url, args.api_key)
    
    try:
        summary = tester.run_all_tests()
        
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Passed: {summary['passed']}")
        print(f"Failed: {summary['failed']}")
        print(f"Success Rate: {summary['success_rate']:.2f}%")
        print(f"Average Duration: {summary['average_duration']:.3f}s")
        print(f"Unique Payloads: {summary['unique_payloads']}")
        print(f"Average Payload Size: {summary['average_payload_size']:.0f} bytes")
        print(f"Average Complexity: {summary['average_complexity']:.1f}")
        
        if summary['failed_tests']:
            print(f"\nFailed Tests: {', '.join(summary['failed_tests'])}")
        
        if args.output:
            tester.save_results(args.output)
        else:
            tester.save_results()
            
    except KeyboardInterrupt:
        logger.info("Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Testing failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
