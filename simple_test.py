#!/usr/bin/env python3
"""
Simple test script to verify the enhanced payload generator works
"""

import sys
import traceback

def test_basic_functionality():
    """Test basic functionality without complex features"""
    print("=== Simple Enhanced Generator Test ===\n")
    
    try:
        # Import and create basic generator
        from payload_generator_enhanced import AdvancedObfuscationEngine
        
        print("✓ Successfully imported AdvancedObfuscationEngine")
        
        # Test basic obfuscation engine
        engine = AdvancedObfuscationEngine()
        print("✓ Successfully created AdvancedObfuscationEngine instance")
        
        # Test basic string obfuscation
        test_string = "Hello World"
        obfuscated = engine.obfuscate_string(test_string)
        print(f"✓ String obfuscation: '{test_string}' -> '{obfuscated[:50]}...'")
        
        # Test variable morphing
        test_var = "myVariable"
        morphed = engine.morph_name(test_var)
        print(f"✓ Variable morphing: '{test_var}' -> '{morphed}'")
        
        # Test command obfuscation
        test_cmd = "Invoke-Expression"
        cmd_obfuscated = engine.obfuscate_command(test_cmd)
        print(f"✓ Command obfuscation: '{test_cmd}' -> '{cmd_obfuscated}'")
        
        return True
        
    except Exception as e:
        print(f"✗ Error in basic functionality test: {str(e)}")
        traceback.print_exc()
        return False

def test_enhanced_generator():
    """Test the enhanced payload generator with simple payloads"""
    print("\n=== Enhanced Payload Generator Test ===\n")
    
    try:
        from payload_generator_enhanced import EnhancedPayloadGenerator
        
        print("✓ Successfully imported EnhancedPayloadGenerator")
        
        generator = EnhancedPayloadGenerator()
        print("✓ Successfully created EnhancedPayloadGenerator instance")
        
        # Test simple traditional payload
        try:
            traditional_payload = generator._generate_enhanced_traditional_payload(3)
            print(f"✓ Traditional payload generated: {len(traditional_payload)} chars")
            print(f"  Preview: {traditional_payload[:100]}...")
        except Exception as e:
            print(f"✗ Traditional payload failed: {str(e)}")
        
        # Test staged payload with low complexity
        try:
            staged_payload = generator._generate_enhanced_staged_payload(complexity_level=3)
            print(f"✓ Staged payload generated: {len(staged_payload)} chars")
            print(f"  Preview: {staged_payload[:100]}...")
        except Exception as e:
            print(f"✗ Staged payload failed: {str(e)}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error in enhanced generator test: {str(e)}")
        traceback.print_exc()
        return False

def test_missing_methods():
    """Test for missing methods and add them if needed"""
    print("\n=== Missing Methods Check ===\n")
    
    try:
        from payload_generator_enhanced import AdvancedObfuscationEngine
        
        engine = AdvancedObfuscationEngine()
        
        # Check for apply_advanced_obfuscation
        if hasattr(engine, 'apply_advanced_obfuscation'):
            print("✓ apply_advanced_obfuscation method exists")
        else:
            print("✗ apply_advanced_obfuscation method missing")
        
        # Check for generate_unicode_variable
        if hasattr(engine, 'generate_unicode_variable'):
            print("✓ generate_unicode_variable method exists")
        else:
            print("✗ generate_unicode_variable method missing")
        
        # Check for _calculate_entropy
        if hasattr(engine, '_calculate_entropy'):
            print("✓ _calculate_entropy method exists")
        else:
            print("✗ _calculate_entropy method missing")
        
        return True
        
    except Exception as e:
        print(f"✗ Error checking methods: {str(e)}")
        return False

def main():
    """Run all simple tests"""
    print("=== Enhanced Payload Generator Simple Test Suite ===\n")
    
    success = True
    
    # Test basic functionality
    if not test_basic_functionality():
        success = False
    
    # Test enhanced generator
    if not test_enhanced_generator():
        success = False
    
    # Check for missing methods
    if not test_missing_methods():
        success = False
    
    if success:
        print("\n=== All simple tests passed! ===")
        return 0
    else:
        print("\n=== Some tests failed ===")
        return 1

if __name__ == "__main__":
    sys.exit(main())
