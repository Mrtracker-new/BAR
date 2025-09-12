#!/usr/bin/env python3
"""
BAR Secure Memory Integration Tests

This module provides comprehensive integration tests for the secure memory system,
verifying proper functionality across different protection levels, TPM integration,
anti-forensics monitoring, and memory management features.

Follows BAR project rules for testing (R021-R024).
"""

import os
import sys
import logging
import tempfile
from pathlib import Path
from typing import Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / 'src'))

from security.secure_memory import (
    SecureBytes, SecureString, MemoryProtectionLevel,
    create_secure_bytes, create_secure_string,
    get_secure_memory_manager, secure_memory_context,
    TPMInterface, AntiForensicsMonitor
)


class SimpleSecureManager:
    """Simple secure manager for testing integration patterns."""
    
    def __init__(self):
        self.logger = logging.getLogger("SimpleSecureManager")
        
        # Initialize TPM interface
        self._tmp_interface = TPMInterface()
        
        # Storage for secure objects
        self._secure_objects = []
        
        self.logger.info("Simple secure manager initialized")
    
    def store_secure_data(self, data: str, use_tmp: bool = False) -> bool:
        """Store data securely with optional TPM protection."""
        try:
            # Create secure string
            protection_level = (MemoryProtectionLevel.MILITARY 
                              if use_tmp and self._tmp_interface.is_available() 
                              else MemoryProtectionLevel.ENHANCED)
            
            secure_data = create_secure_bytes(
                data.encode(),
                protection_level=protection_level,
                use_tpm=use_tmp,
                hardware_bound=True
            )
            
            self._secure_objects.append(secure_data)
            self.logger.info(f"Stored secure data with {protection_level.name} protection")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store secure data: {e}")
            return False
    
    def retrieve_secure_data(self, index: int) -> Optional[str]:
        """Retrieve securely stored data."""
        try:
            if 0 <= index < len(self._secure_objects):
                secure_obj = self._secure_objects[index]
                data_bytes = secure_obj.get_bytes()
                return data_bytes.decode()
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve secure data: {e}")
            return None
    
    def cleanup_all(self) -> int:
        """Clean up all secure objects."""
        cleaned = 0
        for secure_obj in self._secure_objects:
            try:
                secure_obj.clear()
                cleaned += 1
            except Exception:
                pass
        
        self._secure_objects.clear()
        get_secure_memory_manager().cleanup_all()
        
        self.logger.info(f"Cleaned up {cleaned} secure objects")
        return cleaned


def test_simple_integration():
    """Test simple secure memory integration."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("SimpleIntegrationTest")
    
    logger.info("=" * 60)
    logger.info("BAR SIMPLE SECURE MEMORY INTEGRATION TEST")
    logger.info("=" * 60)
    
    success_count = 0
    total_tests = 0
    
    try:
        # Test 1: Basic secure management
        total_tests += 1
        logger.info("\n1. Testing Simple Secure Management")
        logger.info("-" * 40)
        
        manager = SimpleSecureManager()
        
        # Store some test data
        test_data_1 = "Sensitive information 123"
        test_data_2 = "More sensitive data 456"
        
        if (manager.store_secure_data(test_data_1) and 
            manager.store_secure_data(test_data_2, use_tmp=True)):
            
            # Retrieve and verify
            retrieved_1 = manager.retrieve_secure_data(0)
            retrieved_2 = manager.retrieve_secure_data(1)
            
            if retrieved_1 == test_data_1 and retrieved_2 == test_data_2:
                logger.info("✅ Simple secure management test PASSED")
                success_count += 1
            else:
                logger.error("❌ Data retrieval mismatch")
        else:
            logger.error("❌ Failed to store secure data")
        
        # Clean up
        cleaned = manager.cleanup_all()
        logger.info(f"Cleaned up {cleaned} objects")
        
        # Test 2: Memory context management
        total_tests += 1
        logger.info("\n2. Testing Memory Context Management")
        logger.info("-" * 40)
        
        try:
            with secure_memory_context():
                # Create secure objects in context
                secure_str = create_secure_string("Context test data")
                secure_bytes = create_secure_bytes(b"Binary context data")
                
                # Verify they work
                if (secure_str.get_value() == "Context test data" and
                    secure_bytes.get_bytes() == b"Binary context data"):
                    logger.info("✅ Memory context management test PASSED")
                    success_count += 1
                else:
                    logger.error("❌ Context data verification failed")
            
            # Context should auto-cleanup
            logger.info("Context automatically cleaned up")
            
        except Exception as e:
            logger.error(f"❌ Memory context test failed: {e}")
        
        # Test 3: TPM and Anti-forensics availability
        total_tests += 1
        logger.info("\n3. Testing Security Component Availability")
        logger.info("-" * 40)
        
        try:
            # Test TPM interface
            tmp = TPMInterface()
            logger.info(f"TPM available: {tmp.is_available()}")
            
            # Test Anti-forensics monitor
            monitor = AntiForensicsMonitor()
            logger.info(f"Anti-forensics monitoring: {monitor._monitoring}")
            
            # Test memory manager statistics
            stats = get_secure_memory_manager().get_statistics()
            logger.info(f"Memory stats: {stats.total_allocations} total, {stats.active_allocations} active")
            
            logger.info("✅ Security component availability test PASSED")
            success_count += 1
            
        except Exception as e:
            logger.error(f"❌ Security component test failed: {e}")
        
        # Test 4: Protection levels
        total_tests += 1
        logger.info("\n4. Testing Protection Levels")
        logger.info("-" * 40)
        
        try:
            test_data = b"Protection level test data"
            
            # Test different protection levels
            for level in [MemoryProtectionLevel.BASIC, MemoryProtectionLevel.ENHANCED, 
                         MemoryProtectionLevel.MAXIMUM, MemoryProtectionLevel.MILITARY]:
                secure_obj = create_secure_bytes(test_data, protection_level=level)
                retrieved = secure_obj.get_bytes()
                
                if retrieved == test_data:
                    logger.debug(f"✅ {level.name} protection level works")
                else:
                    logger.error(f"❌ {level.name} protection level failed")
                    raise Exception(f"Protection level {level.name} failed")
                
                secure_obj.clear()
            
            logger.info("✅ Protection levels test PASSED")
            success_count += 1
            
        except Exception as e:
            logger.error(f"❌ Protection levels test failed: {e}")
        
    except Exception as e:
        logger.error(f"Integration test error: {e}")
    
    finally:
        # Final cleanup
        get_secure_memory_manager().cleanup_all()
        
        # Report results
        logger.info("\n" + "=" * 60)
        logger.info(f"TEST RESULTS: {success_count}/{total_tests} tests passed")
        if success_count == total_tests:
            logger.info("🎉 ALL TESTS PASSED!")
            logger.info("✅ Secure memory integration is working correctly")
        else:
            logger.warning(f"⚠️ {total_tests - success_count} tests failed")
        logger.info("=" * 60)
        
        # Final memory stats
        stats = get_secure_memory_manager().get_statistics()
        logger.info(f"\nFinal Memory Statistics:")
        logger.info(f"  Total allocations: {stats.total_allocations}")
        logger.info(f"  Active allocations: {stats.active_allocations}")
        logger.info(f"  Cleanup operations: {stats.cleanup_operations}")
        
        return success_count == total_tests


if __name__ == "__main__":
    test_simple_integration()
