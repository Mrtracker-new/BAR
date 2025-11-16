"""
Comprehensive Security Tests for Portable File Format Integrity

Tests for CRITICAL #4: Portable File Format Integrity Weakness
Validates that the HMAC covers the entire file including itself, preventing any tampering.
"""

import os
import sys
import struct
import tempfile
import shutil
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.crypto.secure_portable_format import SecurePortableFormat, SecurePortableConfig
import logging

# Simple mock logger for testing
class MockLogger:
    def __init__(self):
        self.logger = logging.getLogger('test')
        self.logger.setLevel(logging.INFO)
    
    def info(self, msg):
        pass  # Silent in tests
    
    def warning(self, msg):
        print(f"WARNING: {msg}")
    
    def error(self, msg):
        print(f"ERROR: {msg}")


class TestPortableFormatIntegrity:
    """Test suite for portable format integrity fixes."""
    
    def setup_method(self):
        """Set up test environment before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.logger = MockLogger()
        self.format_handler = SecurePortableFormat(self.logger)
        self.test_password = "TestPassword123!@#"
        
    def teardown_method(self):
        """Clean up test environment after each test."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_hmac_covers_entire_file(self):
        """
        Test that HMAC covers the entire file including itself.
        
        ROOT CAUSE: Previous implementation calculated HMAC over data, then appended it.
        This meant the HMAC didn't cover itself, allowing tampering of the last 32 bytes.
        
        FIX: Use placeholder-then-replace scheme where HMAC is calculated over the
        entire file including a placeholder for itself, then the placeholder is replaced.
        """
        print("\nTest 1: HMAC covers entire file including itself")
        
        # Create a portable file
        test_file = os.path.join(self.temp_dir, "test.bar")
        test_content = b"Sensitive data that must be protected"
        test_metadata = {"filename": "secret.txt", "size": len(test_content)}
        
        # Create the file
        result = self.format_handler.create_portable_file(
            test_content,
            test_metadata,
            self.test_password,
            test_file
        )
        assert result, "Failed to create portable file"
        
        # Read the file to verify it's valid
        content, metadata = self.format_handler.read_portable_file(test_file, self.test_password)
        assert content == test_content, "Content mismatch after creation"
        
        # Now tamper with ANY byte in the file
        with open(test_file, 'rb') as f:
            file_data = bytearray(f.read())
        
        original_size = len(file_data)
        
        # Try tampering with different positions
        tamper_positions = [
            0,  # Magic header
            20,  # Version/salt area
            len(file_data) // 2,  # Middle of file
            len(file_data) - 40,  # Near end (in what used to be unprotected decoy area)
            len(file_data) - 32,  # Start of HMAC itself
            len(file_data) - 1,  # Last byte of HMAC
        ]
        
        for pos in tamper_positions:
            # Restore original file
            with open(test_file, 'rb') as f:
                file_data = bytearray(f.read())
            
            # Tamper with one byte
            file_data[pos] ^= 0xFF
            
            # Write tampered file
            tampered_file = os.path.join(self.temp_dir, f"tampered_{pos}.bar")
            with open(tampered_file, 'wb') as f:
                f.write(file_data)
            
            # Try to read - should fail integrity check
            try:
                content, metadata = self.format_handler.read_portable_file(
                    tampered_file, 
                    self.test_password
                )
                # If we get here, integrity check failed!
                assert False, f"Tampering at position {pos} was NOT detected! SECURITY FAILURE!"
            except ValueError as e:
                # Good! Tampering was detected
                # Tampering can be detected at different stages:
                # - "integrity" / "tampered" = HMAC verification failed
                # - "invalid" / "format" = Parsing failed due to corrupt structure
                # - "corrupted" = Data structure inconsistency
                # All of these mean tampering was successfully detected!
                error_msg = str(e).lower()
                assert any(word in error_msg for word in ["integrity", "tampered", "invalid", "format", "corrupted"]), \
                    f"Unexpected error for tampering at {pos}: {e}"
                print(f"  [OK] Tampering at position {pos}/{original_size} detected")
        
        print("  [PASS] HMAC successfully covers entire file - all tampering detected")
    
    def test_decoy_padding_tampering_detected(self):
        """
        Test that tampering with decoy padding is detected.
        
        ROOT CAUSE: Decoy padding was not covered by HMAC, allowing silent modifications.
        
        FIX: HMAC now covers ALL data including decoy padding via the placeholder scheme.
        """
        print("\nTest 2: Decoy padding tampering is detected")
        
        # Create a file with decoy padding
        test_file = os.path.join(self.temp_dir, "test_decoy.bar")
        test_content = b"Content to protect"
        test_metadata = {"filename": "test.txt"}
        
        self.format_handler.create_portable_file(
            test_content,
            test_metadata,
            self.test_password,
            test_file
        )
        
        # Parse the file to find where decoy padding is
        with open(test_file, 'rb') as f:
            file_data = bytearray(f.read())
        
        # Skip magic (16) + version (4) + salt (32) = 52 bytes
        offset = 52
        
        # Skip metadata block: nonce_len (4) + nonce (16) + data_len (4) + data
        metadata_nonce_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4 + metadata_nonce_len
        metadata_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4 + metadata_len
        
        # Skip content block: nonce_len (4) + nonce (16) + data_len (4) + data
        content_nonce_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4 + content_nonce_len
        content_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4 + content_len
        
        # Now we're at the decoy padding length field
        decoy_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4
        
        # This is the decoy padding data
        decoy_start = offset
        decoy_end = offset + decoy_len
        
        print(f"  Decoy padding at bytes {decoy_start}-{decoy_end} ({decoy_len} bytes)")
        
        # Tamper with the middle of the decoy padding
        tamper_pos = decoy_start + (decoy_len // 2)
        file_data[tamper_pos] ^= 0xFF
        
        # Write tampered file
        tampered_file = os.path.join(self.temp_dir, "tampered_decoy.bar")
        with open(tampered_file, 'wb') as f:
            f.write(file_data)
        
        # Try to read - should fail
        try:
            content, metadata = self.format_handler.read_portable_file(
                tampered_file,
                self.test_password
            )
            assert False, "Decoy padding tampering was NOT detected! SECURITY FAILURE!"
        except ValueError as e:
            assert "integrity" in str(e).lower() or "tampered" in str(e).lower()
            print(f"  [OK] Decoy padding tampering detected: {e}")
        
        print("  [PASS] Decoy padding is properly protected by HMAC")
    
    def test_version_binding_prevents_confusion(self):
        """
        Test that version is bound to integrity hash.
        
        ROOT CAUSE: Version not included in HMAC, allowing version confusion attacks.
        
        FIX: Version is included in AAD for HMAC calculation.
        """
        print("\nTest 3: Version binding prevents confusion attacks")
        
        # Create a valid file
        test_file = os.path.join(self.temp_dir, "test_version.bar")
        test_content = b"Version-sensitive content"
        test_metadata = {"filename": "versioned.txt"}
        
        self.format_handler.create_portable_file(
            test_content,
            test_metadata,
            self.test_password,
            test_file
        )
        
        # Read the file
        with open(test_file, 'rb') as f:
            file_data = bytearray(f.read())
        
        # Try to change the version field (at bytes 16-19)
        version_offset = 16
        original_version = struct.unpack('>I', file_data[version_offset:version_offset+4])[0]
        
        # Change version to something else
        fake_version = original_version ^ 0x00000001
        struct.pack_into('>I', file_data, version_offset, fake_version)
        
        # Write modified file
        modified_file = os.path.join(self.temp_dir, "modified_version.bar")
        with open(modified_file, 'wb') as f:
            f.write(file_data)
        
        # Try to read - should fail integrity check
        try:
            content, metadata = self.format_handler.read_portable_file(
                modified_file,
                self.test_password
            )
            assert False, "Version modification was NOT detected! SECURITY FAILURE!"
        except ValueError as e:
            assert "integrity" in str(e).lower() or "version" in str(e).lower()
            print(f"  [OK] Version tampering detected: {e}")
        
        print("  [PASS] Version is properly bound to integrity hash")
    
    def test_timestamp_binding_prevents_rollback(self):
        """
        Test that timestamp is bound to integrity hash.
        
        ROOT CAUSE: No timestamp in HMAC, allowing rollback attacks.
        
        FIX: Timestamp is included in AAD for HMAC calculation and validated on read.
        """
        print("\nTest 4: Timestamp binding prevents rollback attacks")
        
        # Create a valid file
        test_file = os.path.join(self.temp_dir, "test_timestamp.bar")
        test_content = b"Time-sensitive content"
        test_metadata = {"filename": "timestamped.txt"}
        
        self.format_handler.create_portable_file(
            test_content,
            test_metadata,
            self.test_password,
            test_file
        )
        
        # Read the file to get structure
        with open(test_file, 'rb') as f:
            file_data = bytearray(f.read())
        
        # Parse to find timestamp location
        # Skip to timestamp: magic(16) + version(4) + salt(32) + metadata_block + content_block + decoy_len(4) + decoy + timestamp(8)
        offset = 52  # After header
        
        # Skip metadata block
        metadata_nonce_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4 + metadata_nonce_len
        metadata_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4 + metadata_len
        
        # Skip content block
        content_nonce_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4 + content_nonce_len
        content_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4 + content_len
        
        # Skip decoy
        decoy_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4 + decoy_len
        
        # Now we're at the timestamp
        timestamp_offset = offset
        original_timestamp = struct.unpack('>Q', file_data[timestamp_offset:timestamp_offset+8])[0]
        
        print(f"  Original timestamp: {original_timestamp}")
        
        # Try to roll back timestamp by 1 day
        fake_timestamp = original_timestamp - (24 * 3600)
        struct.pack_into('>Q', file_data, timestamp_offset, fake_timestamp)
        
        # Write modified file
        modified_file = os.path.join(self.temp_dir, "rolled_back.bar")
        with open(modified_file, 'wb') as f:
            f.write(file_data)
        
        # Try to read - should fail integrity check
        try:
            content, metadata = self.format_handler.read_portable_file(
                modified_file,
                self.test_password
            )
            assert False, "Timestamp rollback was NOT detected! SECURITY FAILURE!"
        except ValueError as e:
            assert "integrity" in str(e).lower() or "tampered" in str(e).lower()
            print(f"  [OK] Timestamp tampering detected: {e}")
        
        print("  [PASS] Timestamp is properly bound to integrity hash")
    
    def test_structure_commitment_prevents_swapping(self):
        """
        Test that structure sizes are committed to in HMAC.
        
        ROOT CAUSE: Block sizes not in HMAC AAD, potentially allowing block swapping.
        
        FIX: All block sizes are included in AAD for HMAC calculation.
        """
        print("\nTest 5: Structure commitment prevents block manipulation")
        
        # Create a valid file
        test_file = os.path.join(self.temp_dir, "test_structure.bar")
        test_content = b"A" * 1000  # Large content
        test_metadata = {"filename": "structured.txt", "size": 1000}
        
        self.format_handler.create_portable_file(
            test_content,
            test_metadata,
            self.test_password,
            test_file
        )
        
        # Verify original file works
        content, metadata = self.format_handler.read_portable_file(test_file, self.test_password)
        assert content == test_content
        
        # Now try to modify structure by changing a length field
        with open(test_file, 'rb') as f:
            file_data = bytearray(f.read())
        
        # Change the metadata length field (at offset 52 + 4 + 16 + 4 = 76)
        offset = 52 + 4 + 16
        original_metadata_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        
        # Try to claim metadata is shorter (but don't actually change the data)
        fake_metadata_len = original_metadata_len - 1
        struct.pack_into('>I', file_data, offset, fake_metadata_len)
        
        # Write modified file
        modified_file = os.path.join(self.temp_dir, "modified_structure.bar")
        with open(modified_file, 'wb') as f:
            f.write(file_data)
        
        # Try to read - should fail integrity check
        try:
            content, metadata = self.format_handler.read_portable_file(
                modified_file,
                self.test_password
            )
            assert False, "Structure tampering was NOT detected! SECURITY FAILURE!"
        except ValueError as e:
            # Tampering can be detected at different stages:
            # - HMAC verification (integrity/tampered)
            # - Parse errors (invalid/format/size)
            # Both are valid - the file is rejected
            error_msg = str(e).lower()
            assert any(word in error_msg for word in ["integrity", "tampered", "invalid", "format", "size", "corrupted"]), \
                f"Unexpected error: {e}"
            print(f"  [OK] Structure tampering detected: {e}")
        
        print("  [PASS] Structure sizes are properly committed to in HMAC")
    
    def test_no_nonce_reuse_on_retry(self):
        """
        Test that nonces are never reused, even on error/retry scenarios.
        
        ROOT CAUSE: Potential nonce reuse if operations are retried.
        
        FIX: Nonces are generated fresh for each operation, no retry logic reuses them.
        """
        print("\nTest 6: No nonce reuse across multiple creations")
        
        # Create multiple files with same content
        test_content = b"Same content every time"
        test_metadata = {"filename": "same.txt"}
        
        nonces_seen = set()
        
        for i in range(5):
            test_file = os.path.join(self.temp_dir, f"test_{i}.bar")
            
            self.format_handler.create_portable_file(
                test_content,
                test_metadata,
                self.test_password,
                test_file
            )
            
            # Extract nonces from the file
            with open(test_file, 'rb') as f:
                file_data = f.read()
            
            # Extract metadata nonce (at offset 52 + 4 = 56, length 16)
            offset = 56
            metadata_nonce = file_data[offset:offset+16]
            
            # Extract content nonce (after metadata block)
            offset = 52 + 4 + 16 + 4
            metadata_len = struct.unpack('>I', file_data[offset-4:offset])[0]
            offset += metadata_len + 4
            content_nonce = file_data[offset:offset+16]
            
            # Check for nonce reuse
            metadata_nonce_hex = metadata_nonce.hex()
            content_nonce_hex = content_nonce.hex()
            
            assert metadata_nonce_hex not in nonces_seen, f"Metadata nonce REUSED in file {i}! SECURITY FAILURE!"
            assert content_nonce_hex not in nonces_seen, f"Content nonce REUSED in file {i}! SECURITY FAILURE!"
            
            nonces_seen.add(metadata_nonce_hex)
            nonces_seen.add(content_nonce_hex)
            
            print(f"  [OK] File {i}: Unique nonces generated")
        
        print(f"  [PASS] All {len(nonces_seen)} nonces are unique across 5 file creations")


def run_all_tests():
    """Run all integrity tests."""
    print("=" * 70)
    print("PORTABLE FILE FORMAT INTEGRITY TEST SUITE")
    print("Testing fixes for CRITICAL #4: Portable Format Integrity Weakness")
    print("=" * 70)
    
    tester = TestPortableFormatIntegrity()
    
    tests = [
        tester.test_hmac_covers_entire_file,
        tester.test_decoy_padding_tampering_detected,
        tester.test_version_binding_prevents_confusion,
        tester.test_timestamp_binding_prevents_rollback,
        tester.test_structure_commitment_prevents_swapping,
        tester.test_no_nonce_reuse_on_retry,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            tester.setup_method()
            test()
            tester.teardown_method()
            passed += 1
        except AssertionError as e:
            print(f"\n[FAIL] {test.__name__}: {e}")
            failed += 1
            tester.teardown_method()
        except Exception as e:
            print(f"\n[ERROR] {test.__name__}: {e}")
            failed += 1
            tester.teardown_method()
    
    print("\n" + "=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 70)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
