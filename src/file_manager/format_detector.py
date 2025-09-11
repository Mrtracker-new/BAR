"""
Enhanced file format detection system for the BAR application.

This module provides comprehensive file format detection using multiple methods:
- File extension analysis
- Magic bytes/file signature detection
- MIME type detection
- Content analysis for specific formats

Author: Rolan Lobo (RNR)
Project: BAR - Burn After Reading Security Suite
"""

import os
import mimetypes
import struct
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
import logging


class FileFormatDetector:
    """Advanced file format detection with comprehensive format support."""
    
    # File signatures (magic bytes) for format detection
    FILE_SIGNATURES = {
        # Images
        b'\xff\xd8\xff': {'type': 'image', 'format': 'jpeg', 'mime': 'image/jpeg', 'viewable': True},
        b'\x89PNG\r\n\x1a\n': {'type': 'image', 'format': 'png', 'mime': 'image/png', 'viewable': True},
        b'GIF87a': {'type': 'image', 'format': 'gif', 'mime': 'image/gif', 'viewable': True},
        b'GIF89a': {'type': 'image', 'format': 'gif', 'mime': 'image/gif', 'viewable': True},
        b'BM': {'type': 'image', 'format': 'bmp', 'mime': 'image/bmp', 'viewable': True},
        b'RIFF': {'type': 'image', 'format': 'webp', 'mime': 'image/webp', 'viewable': True},  # Could also be audio
        b'MM\x00*': {'type': 'image', 'format': 'tiff', 'mime': 'image/tiff', 'viewable': True},
        b'II*\x00': {'type': 'image', 'format': 'tiff', 'mime': 'image/tiff', 'viewable': True},
        
        # Audio
        b'ID3': {'type': 'audio', 'format': 'mp3', 'mime': 'audio/mpeg', 'viewable': False},
        b'\xff\xfb': {'type': 'audio', 'format': 'mp3', 'mime': 'audio/mpeg', 'viewable': False},
        b'fLaC': {'type': 'audio', 'format': 'flac', 'mime': 'audio/flac', 'viewable': False},
        b'OggS': {'type': 'audio', 'format': 'ogg', 'mime': 'audio/ogg', 'viewable': False},
        
        # Video
        b'\x00\x00\x00\x18ftyp': {'type': 'video', 'format': 'mp4', 'mime': 'video/mp4', 'viewable': False},
        b'\x00\x00\x00\x20ftyp': {'type': 'video', 'format': 'mp4', 'mime': 'video/mp4', 'viewable': False},
        b'RIFF????WEBP': {'type': 'video', 'format': 'webm', 'mime': 'video/webm', 'viewable': False},
        b'\x1aE\xdf\xa3': {'type': 'video', 'format': 'mkv', 'mime': 'video/x-matroska', 'viewable': False},
        
        # Documents
        b'%PDF': {'type': 'document', 'format': 'pdf', 'mime': 'application/pdf', 'viewable': True},
        b'PK\x03\x04': {'type': 'document', 'format': 'zip', 'mime': 'application/zip', 'viewable': False},  # Could be Office
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': {'type': 'document', 'format': 'ole', 'mime': 'application/x-ole-storage', 'viewable': False},
        
        # Archives
        b'7z\xbc\xaf\x27\x1c': {'type': 'archive', 'format': '7z', 'mime': 'application/x-7z-compressed', 'viewable': False},
        b'Rar!\x1a\x07\x00': {'type': 'archive', 'format': 'rar', 'mime': 'application/x-rar-compressed', 'viewable': False},
        b'\x1f\x8b\x08': {'type': 'archive', 'format': 'gzip', 'mime': 'application/gzip', 'viewable': False},
        
        # Executables
        b'MZ': {'type': 'executable', 'format': 'exe', 'mime': 'application/x-msdownload', 'viewable': False},
        b'\x7fELF': {'type': 'executable', 'format': 'elf', 'mime': 'application/x-executable', 'viewable': False},
        
        # Other formats
        b'SQLite format 3': {'type': 'database', 'format': 'sqlite', 'mime': 'application/x-sqlite3', 'viewable': False},
    }
    
    # File extension mappings
    EXTENSION_MAP = {
        # Images
        '.jpg': {'type': 'image', 'format': 'jpeg', 'mime': 'image/jpeg', 'viewable': True},
        '.jpeg': {'type': 'image', 'format': 'jpeg', 'mime': 'image/jpeg', 'viewable': True},
        '.png': {'type': 'image', 'format': 'png', 'mime': 'image/png', 'viewable': True},
        '.gif': {'type': 'image', 'format': 'gif', 'mime': 'image/gif', 'viewable': True},
        '.bmp': {'type': 'image', 'format': 'bmp', 'mime': 'image/bmp', 'viewable': True},
        '.webp': {'type': 'image', 'format': 'webp', 'mime': 'image/webp', 'viewable': True},
        '.tiff': {'type': 'image', 'format': 'tiff', 'mime': 'image/tiff', 'viewable': True},
        '.tif': {'type': 'image', 'format': 'tiff', 'mime': 'image/tiff', 'viewable': True},
        '.svg': {'type': 'image', 'format': 'svg', 'mime': 'image/svg+xml', 'viewable': True},
        '.ico': {'type': 'image', 'format': 'ico', 'mime': 'image/x-icon', 'viewable': True},
        
        # Audio
        '.mp3': {'type': 'audio', 'format': 'mp3', 'mime': 'audio/mpeg', 'viewable': False, 'external': True},
        '.wav': {'type': 'audio', 'format': 'wav', 'mime': 'audio/wav', 'viewable': False, 'external': True},
        '.flac': {'type': 'audio', 'format': 'flac', 'mime': 'audio/flac', 'viewable': False, 'external': True},
        '.ogg': {'type': 'audio', 'format': 'ogg', 'mime': 'audio/ogg', 'viewable': False, 'external': True},
        '.aac': {'type': 'audio', 'format': 'aac', 'mime': 'audio/aac', 'viewable': False, 'external': True},
        '.m4a': {'type': 'audio', 'format': 'm4a', 'mime': 'audio/mp4', 'viewable': False, 'external': True},
        
        # Video
        '.mp4': {'type': 'video', 'format': 'mp4', 'mime': 'video/mp4', 'viewable': False, 'external': True},
        '.avi': {'type': 'video', 'format': 'avi', 'mime': 'video/x-msvideo', 'viewable': False, 'external': True},
        '.mkv': {'type': 'video', 'format': 'mkv', 'mime': 'video/x-matroska', 'viewable': False, 'external': True},
        '.mov': {'type': 'video', 'format': 'mov', 'mime': 'video/quicktime', 'viewable': False, 'external': True},
        '.wmv': {'type': 'video', 'format': 'wmv', 'mime': 'video/x-ms-wmv', 'viewable': False, 'external': True},
        '.webm': {'type': 'video', 'format': 'webm', 'mime': 'video/webm', 'viewable': False, 'external': True},
        '.flv': {'type': 'video', 'format': 'flv', 'mime': 'video/x-flv', 'viewable': False, 'external': True},
        
        # Documents
        '.pdf': {'type': 'document', 'format': 'pdf', 'mime': 'application/pdf', 'viewable': True, 'external': True},
        '.txt': {'type': 'text', 'format': 'plain', 'mime': 'text/plain', 'viewable': True},
        '.rtf': {'type': 'document', 'format': 'rtf', 'mime': 'application/rtf', 'viewable': False, 'external': True},
        '.doc': {'type': 'document', 'format': 'doc', 'mime': 'application/msword', 'viewable': False, 'external': True},
        '.docx': {'type': 'document', 'format': 'docx', 'mime': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'viewable': False, 'external': True},
        '.xls': {'type': 'document', 'format': 'xls', 'mime': 'application/vnd.ms-excel', 'viewable': False, 'external': True},
        '.xlsx': {'type': 'document', 'format': 'xlsx', 'mime': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'viewable': False, 'external': True},
        '.ppt': {'type': 'document', 'format': 'ppt', 'mime': 'application/vnd.ms-powerpoint', 'viewable': False, 'external': True},
        '.pptx': {'type': 'document', 'format': 'pptx', 'mime': 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'viewable': False, 'external': True},
        
        # Code/Text
        '.py': {'type': 'code', 'format': 'python', 'mime': 'text/x-python', 'viewable': True},
        '.js': {'type': 'code', 'format': 'javascript', 'mime': 'text/javascript', 'viewable': True},
        '.html': {'type': 'code', 'format': 'html', 'mime': 'text/html', 'viewable': True},
        '.css': {'type': 'code', 'format': 'css', 'mime': 'text/css', 'viewable': True},
        '.json': {'type': 'data', 'format': 'json', 'mime': 'application/json', 'viewable': True},
        '.xml': {'type': 'data', 'format': 'xml', 'mime': 'text/xml', 'viewable': True},
        '.csv': {'type': 'data', 'format': 'csv', 'mime': 'text/csv', 'viewable': True},
        
        # Archives
        '.zip': {'type': 'archive', 'format': 'zip', 'mime': 'application/zip', 'viewable': False},
        '.rar': {'type': 'archive', 'format': 'rar', 'mime': 'application/x-rar-compressed', 'viewable': False},
        '.7z': {'type': 'archive', 'format': '7z', 'mime': 'application/x-7z-compressed', 'viewable': False},
        '.tar': {'type': 'archive', 'format': 'tar', 'mime': 'application/x-tar', 'viewable': False},
        '.gz': {'type': 'archive', 'format': 'gzip', 'mime': 'application/gzip', 'viewable': False},
        
        # Executables
        '.exe': {'type': 'executable', 'format': 'exe', 'mime': 'application/x-msdownload', 'viewable': False},
        '.msi': {'type': 'executable', 'format': 'msi', 'mime': 'application/x-msi', 'viewable': False},
        '.deb': {'type': 'executable', 'format': 'deb', 'mime': 'application/x-debian-package', 'viewable': False},
        '.rpm': {'type': 'executable', 'format': 'rpm', 'mime': 'application/x-rpm', 'viewable': False},
        
        # Other
        '.db': {'type': 'database', 'format': 'db', 'mime': 'application/x-sqlite3', 'viewable': False},
        '.sqlite': {'type': 'database', 'format': 'sqlite', 'mime': 'application/x-sqlite3', 'viewable': False},
    }
    
    def __init__(self):
        """Initialize the format detector."""
        self.logger = logging.getLogger(__name__)
        # Initialize mimetypes
        mimetypes.init()
    
    def detect_format(self, filename: str, content: bytes = None) -> Dict[str, Any]:
        """
        Detect file format using multiple methods.
        
        Args:
            filename: The filename to analyze
            content: Optional file content for signature detection
            
        Returns:
            Dictionary containing format information:
            {
                'type': 'image|audio|video|document|text|code|archive|executable|unknown',
                'format': 'specific_format_name',
                'mime': 'mime/type',
                'viewable': bool,  # Can be viewed in-app
                'external': bool,  # Can be opened with external app
                'confidence': int,  # 0-100 confidence level
                'detection_method': 'extension|signature|mime|content',
                'display_name': 'Human readable format name',
                'icon': 'icon_name_for_ui',
                'viewer_message': 'Message to show in viewer'
            }
        """
        # Start with unknown format
        result = {
            'type': 'unknown',
            'format': 'unknown',
            'mime': 'application/octet-stream',
            'viewable': False,
            'external': False,
            'confidence': 0,
            'detection_method': 'none',
            'display_name': 'Unknown File',
            'icon': 'file-unknown',
            'viewer_message': 'This file format is not recognized and cannot be displayed.'
        }
        
        # Try content-based detection first (highest confidence)
        if content and len(content) > 0:
            signature_result = self._detect_by_signature(content)
            if signature_result['confidence'] > result['confidence']:
                result.update(signature_result)
        
        # Try extension-based detection
        extension_result = self._detect_by_extension(filename)
        if extension_result['confidence'] > result['confidence']:
            result.update(extension_result)
        
        # Try MIME type detection
        mime_result = self._detect_by_mime(filename)
        if mime_result['confidence'] > result['confidence']:
            result.update(mime_result)
        
        # Enhance with display information
        self._enhance_format_info(result)
        
        return result
    
    def _detect_by_signature(self, content: bytes) -> Dict[str, Any]:
        """Detect format by file signature (magic bytes)."""
        result = {'confidence': 0, 'detection_method': 'signature'}
        
        # Check first 16 bytes for signatures
        header = content[:16] if len(content) >= 16 else content
        
        for signature, info in self.FILE_SIGNATURES.items():
            if header.startswith(signature):
                result.update(info)
                result['confidence'] = 90
                result['detection_method'] = 'signature'
                break
        
        # Special case for RIFF files (could be WebP or AVI)
        if header.startswith(b'RIFF') and len(content) > 12:
            # Check RIFF type
            riff_type = content[8:12]
            if riff_type == b'WEBP':
                result.update({
                    'type': 'image',
                    'format': 'webp',
                    'mime': 'image/webp',
                    'viewable': True,
                    'confidence': 95
                })
            elif riff_type == b'AVI ':
                result.update({
                    'type': 'video',
                    'format': 'avi',
                    'mime': 'video/x-msvideo',
                    'viewable': False,
                    'external': True,
                    'confidence': 95
                })
        
        # Special case for ZIP-based formats (Office documents)
        if header.startswith(b'PK\x03\x04'):
            result.update({
                'type': 'archive',
                'format': 'zip',
                'mime': 'application/zip',
                'viewable': False,
                'confidence': 80
            })
        
        return result
    
    def _detect_by_extension(self, filename: str) -> Dict[str, Any]:
        """Detect format by file extension."""
        result = {'confidence': 0, 'detection_method': 'extension'}
        
        _, ext = os.path.splitext(filename.lower())
        if ext in self.EXTENSION_MAP:
            result.update(self.EXTENSION_MAP[ext])
            result['confidence'] = 70
            result['detection_method'] = 'extension'
        
        return result
    
    def _detect_by_mime(self, filename: str) -> Dict[str, Any]:
        """Detect format using Python's mimetypes module."""
        result = {'confidence': 0, 'detection_method': 'mime'}
        
        mime_type, encoding = mimetypes.guess_type(filename)
        if mime_type:
            result['mime'] = mime_type
            result['confidence'] = 50
            result['detection_method'] = 'mime'
            
            # Map MIME type to our categories
            if mime_type.startswith('image/'):
                result.update({
                    'type': 'image',
                    'viewable': True,
                    'confidence': 60
                })
            elif mime_type.startswith('audio/'):
                result.update({
                    'type': 'audio',
                    'viewable': False,
                    'external': True,
                    'confidence': 60
                })
            elif mime_type.startswith('video/'):
                result.update({
                    'type': 'video',
                    'viewable': False,
                    'external': True,
                    'confidence': 60
                })
            elif mime_type.startswith('text/'):
                result.update({
                    'type': 'text',
                    'viewable': True,
                    'confidence': 60
                })
            elif mime_type in ['application/pdf']:
                result.update({
                    'type': 'document',
                    'format': 'pdf',
                    'viewable': True,
                    'external': True,
                    'confidence': 70
                })
        
        return result
    
    def _enhance_format_info(self, result: Dict[str, Any]):
        """Enhance format result with display information."""
        file_type = result['type']
        file_format = result['format']
        
        # Set display name
        format_names = {
            'jpeg': 'JPEG Image',
            'png': 'PNG Image',
            'gif': 'GIF Image',
            'bmp': 'Bitmap Image',
            'webp': 'WebP Image',
            'tiff': 'TIFF Image',
            'svg': 'SVG Vector Image',
            'ico': 'Icon File',
            'mp3': 'MP3 Audio',
            'wav': 'WAV Audio',
            'flac': 'FLAC Audio',
            'ogg': 'OGG Audio',
            'aac': 'AAC Audio',
            'm4a': 'M4A Audio',
            'mp4': 'MP4 Video',
            'avi': 'AVI Video',
            'mkv': 'MKV Video',
            'mov': 'QuickTime Video',
            'wmv': 'Windows Media Video',
            'webm': 'WebM Video',
            'flv': 'Flash Video',
            'pdf': 'PDF Document',
            'doc': 'Word Document',
            'docx': 'Word Document',
            'xls': 'Excel Spreadsheet',
            'xlsx': 'Excel Spreadsheet',
            'ppt': 'PowerPoint Presentation',
            'pptx': 'PowerPoint Presentation',
            'txt': 'Text File',
            'rtf': 'Rich Text Document',
            'python': 'Python Code',
            'javascript': 'JavaScript Code',
            'html': 'HTML Document',
            'css': 'CSS Stylesheet',
            'json': 'JSON Data',
            'xml': 'XML Document',
            'csv': 'CSV Data',
            'zip': 'ZIP Archive',
            'rar': 'RAR Archive',
            '7z': '7-Zip Archive',
            'tar': 'TAR Archive',
            'gzip': 'GZIP Archive',
            'exe': 'Executable File',
            'msi': 'Windows Installer',
            'sqlite': 'SQLite Database',
        }
        
        result['display_name'] = format_names.get(file_format, f"{file_type.title()} File")
        
        # Set icon
        icon_map = {
            'image': 'file-image',
            'audio': 'file-audio',
            'video': 'file-video',
            'document': 'file-text',
            'text': 'file-text',
            'code': 'file-code',
            'archive': 'file-archive',
            'executable': 'file-executable',
            'database': 'file-database',
            'unknown': 'file-unknown'
        }
        result['icon'] = icon_map.get(file_type, 'file-unknown')
        
        # Set viewer message
        if result['viewable']:
            if file_type == 'image':
                result['viewer_message'] = 'This image can be displayed directly in the application.'
            elif file_type == 'text' or file_type == 'code':
                result['viewer_message'] = 'This text file can be displayed directly in the application.'
            elif file_type == 'document' and file_format == 'pdf':
                result['viewer_message'] = 'This PDF can be viewed in the application or opened with an external PDF viewer.'
            else:
                result['viewer_message'] = 'This file can be displayed in the application.'
        elif result.get('external', False):
            if file_type == 'audio':
                result['viewer_message'] = f'This {result["display_name"]} can be played using your default audio player.'
            elif file_type == 'video':
                result['viewer_message'] = f'This {result["display_name"]} can be played using your default video player.'
            elif file_type == 'document':
                result['viewer_message'] = f'This {result["display_name"]} can be opened with the appropriate application (e.g., Microsoft Office, LibreOffice).'
            else:
                result['viewer_message'] = f'This {result["display_name"]} can be opened with an external application.'
        else:
            if file_type == 'archive':
                result['viewer_message'] = 'This archive file contains compressed data and cannot be viewed directly. Export it to extract the contents.'
            elif file_type == 'executable':
                result['viewer_message'] = 'This executable file cannot be viewed for security reasons. Export it to run on your system.'
            elif file_type == 'database':
                result['viewer_message'] = 'This database file cannot be viewed directly. Export it to open with a database application.'
            else:
                result['viewer_message'] = 'This file format cannot be displayed. Export it to open with an appropriate application.'
    
    def get_viewable_formats(self) -> List[str]:
        """Get list of formats that can be viewed in-app."""
        viewable = []
        for ext, info in self.EXTENSION_MAP.items():
            if info.get('viewable', False):
                viewable.append(ext)
        return sorted(viewable)
    
    def get_external_formats(self) -> List[str]:
        """Get list of formats that can be opened externally."""
        external = []
        for ext, info in self.EXTENSION_MAP.items():
            if info.get('external', False):
                external.append(ext)
        return sorted(external)
    
    def is_media_file(self, filename: str, content: bytes = None) -> bool:
        """Check if file is a media file (image, audio, video)."""
        format_info = self.detect_format(filename, content)
        return format_info['type'] in ['image', 'audio', 'video']
    
    def is_viewable(self, filename: str, content: bytes = None) -> bool:
        """Check if file can be viewed in-app."""
        format_info = self.detect_format(filename, content)
        return format_info['viewable']
    
    def can_open_externally(self, filename: str, content: bytes = None) -> bool:
        """Check if file can be opened with external applications."""
        format_info = self.detect_format(filename, content)
        return format_info.get('external', False)
