import os
import sys
import subprocess
import tempfile
from typing import Optional, Dict, Any, Callable

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea,
    QPushButton, QMessageBox, QSizePolicy, QFrame,
    QFormLayout, QTabWidget, QPlainTextEdit
)
from PySide6.QtCore import Qt, Signal as pyqtSignal, QThread, Slot as pyqtSlot, QPointF
from PySide6.QtGui import QPixmap, QImage, QFont, QColor, QSyntaxHighlighter, QTextCharFormat, QPainter, QPen

# Using the ultimate consolidated screen protection system
# All screenshot prevention features are now consolidated in this enhanced module
from ..security.ENHANCED_advanced_screen_protection import AdvancedScreenProtectionManager
from ..file_manager.format_detector import FileFormatDetector
from .styles import StyleManager


class SimpleWatermarker:
    """Simple watermarker for view-only files - extracted from legacy protection."""
    
    def __init__(self, username: str):
        self.username = username
    
    def apply_text_watermark(self, text_edit):
        """Apply watermark to text content."""
        import time
        current_text = text_edit.toPlainText()
        timestamp = time.strftime("%Y-%m-%d %H:%M")
        watermark_header = f"--- Viewed by {self.username} at {timestamp} ---\n\n"
        watermark_footer = f"\n\n--- Protected content - Do not distribute ---"
        watermarked_text = watermark_header + current_text + watermark_footer
        text_edit.setPlainText(watermarked_text)
        text_edit.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByKeyboard | Qt.TextInteractionFlag.TextSelectableByMouse)
        text_edit.setStyleSheet(
            "background: repeating-linear-gradient(45deg, transparent, "
            "transparent 100px, rgba(200, 200, 200, 0.1) 100px, "
            "rgba(200, 200, 200, 0.1) 200px);"
        )
    
    def apply_image_watermark(self, image_label, pixmap):
        """Apply watermark to image content."""
        import time
        try:
            if pixmap.isNull() or pixmap.width() <= 0 or pixmap.height() <= 0:
                return pixmap
            if pixmap.width() * pixmap.height() > 25000000:
                return pixmap
            
            watermarked_pixmap = pixmap.copy()
            painter = QPainter()
            if not painter.begin(watermarked_pixmap):
                return pixmap
            
            try:
                painter.setOpacity(0.8)
                painter.setPen(QPen(QColor(255, 0, 0, 255)))
                font_size = max(14, min(24, watermarked_pixmap.width() // 30))
                font = QFont("Arial", font_size)
                font.setBold(True)
                painter.setFont(font)
                
                timestamp = time.strftime("%Y-%m-%d %H:%M")
                watermark_text = f"Viewed by {self.username} at {timestamp}"
                
                painter.save()
                painter.translate(watermarked_pixmap.width() / 2, watermarked_pixmap.height() / 2)
                painter.rotate(-45)
                # Use horizontalAdvance() instead of width() for PySide6 compatibility
                text_width = painter.fontMetrics().horizontalAdvance(watermark_text)
                painter.drawText(QPointF(-text_width / 2, 0), watermark_text)
                painter.restore()
                
                painter.setOpacity(0.9)
                painter.setPen(QPen(QColor(255, 0, 0, 255), 5))
                painter.drawRect(5, 5, watermarked_pixmap.width() - 10, watermarked_pixmap.height() - 10)
            finally:
                painter.end()
            
            return watermarked_pixmap
        except Exception as e:
            print(f"Error applying watermark: {e}")
            return pixmap


class PythonSyntaxHighlighter(QSyntaxHighlighter):
    """Simple Python syntax highlighter."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Define highlighting rules
        self.highlighting_rules = []
        
        # Python keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569cd6"))
        keyword_format.setFontWeight(QFont.Weight.Bold)
        keywords = [
            "and", "as", "assert", "break", "class", "continue", "def",
            "del", "elif", "else", "except", "exec", "finally", "for",
            "from", "global", "if", "import", "in", "is", "lambda",
            "not", "or", "pass", "print", "raise", "return", "try",
            "while", "with", "yield"
        ]
        for keyword in keywords:
            self.highlighting_rules.append((f"\\b{keyword}\\b", keyword_format))
        
        # String literals
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#ce9178"))
        self.highlighting_rules.append((r'".*"', string_format))
        self.highlighting_rules.append((r"'.*'", string_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6a9955"))
        self.highlighting_rules.append((r"#.*", comment_format))
    
    def highlightBlock(self, text):
        """Apply syntax highlighting to a block of text."""
        import re
        for pattern, format in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                start, end = match.span()
                self.setFormat(start, end - start, format)


class ExternalViewerThread(QThread):
    """Thread for launching external viewers safely."""
    
    finished_signal = pyqtSignal(bool, str)  # success, message
    
    def __init__(self, file_path: str, file_format: Dict[str, Any]):
        super().__init__()
        self.file_path = file_path
        self.file_format = file_format
    
    def run(self):
        """Launch external viewer."""
        try:
            if os.name == 'nt':  # Windows
                os.startfile(self.file_path)
            elif os.name == 'posix':  # Linux/macOS
                if sys.platform == 'darwin':  # macOS
                    subprocess.run(['open', self.file_path], check=True)
                else:  # Linux
                    subprocess.run(['xdg-open', self.file_path], check=True)
            
            self.finished_signal.emit(True, f"Opened {self.file_format['display_name']} with external application.")
        except Exception as e:
            self.finished_signal.emit(False, f"Failed to open with external application: {str(e)}")


class FileViewer(QWidget):
    """Enhanced file viewer with comprehensive format support and intelligent feedback."""
    
    # Signal emitted when the user requests to close the viewer
    close_requested = pyqtSignal()
    # Signal emitted when export is requested
    export_requested = pyqtSignal()
    
    def __init__(self, parent=None):
        """Initialize the enhanced file viewer.
        
        Args:
            parent: The parent widget
        """
        super().__init__(parent)
        
        # Initialize components
        self.format_detector = FileFormatDetector()
        self.content_type = "unknown"
        self.is_view_only = False
        self.username = ""
        self.watermarker = None
        self.current_content = None
        self.current_metadata = None
        self.current_format_info = None
        self.export_handler = None
        self.temp_files = []  # Track temporary files for cleanup
        
        # Set up exception handling
        sys.excepthook = self._handle_uncaught_exception
        
        self._setup_ui()
        
    def _handle_uncaught_exception(self, exc_type, exc_value, exc_traceback):
        """Handle uncaught exceptions to prevent app crashes.
        
        Args:
            exc_type: Exception type
            exc_value: Exception value
            exc_traceback: Exception traceback
        """
        # Log the error
        import traceback
        error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        print(f"Uncaught exception in FileViewer: {error_msg}")
        
        # Show error message to user if possible
        try:
            QMessageBox.critical(self, "Error", 
                                "An error occurred while processing the file. \n\n" + 
                                str(exc_value))
        except:
            pass
        
        # Restore default exception handler
        sys.excepthook = sys.__excepthook__
    
    def _setup_ui(self):
        """Set up the user interface."""
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        # Content area with tabs (Viewer and Details)
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        
        # Viewer tab
        self.viewer_tab = QWidget()
        self.viewer_layout = QVBoxLayout(self.viewer_tab)
        self.tabs.addTab(self.viewer_tab, "Viewer")
        
        # Content area
        self.content_area = QScrollArea()
        self.content_area.setWidgetResizable(True)
        self.content_area.setFrameShape(QFrame.NoFrame)
        self.viewer_layout.addWidget(self.content_area)
        
        # Text content widget
        self.text_widget = QPlainTextEdit()
        self.text_widget.setReadOnly(True)
        self.text_widget.setVisible(False)
        
        # Image content widget
        self.image_container = QWidget()
        self.image_layout = QVBoxLayout(self.image_container)
        self.image_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.image_layout.addWidget(self.image_label)
        
        # Binary content widget (placeholder for unsupported content)
        self.binary_widget = QWidget()
        self.binary_layout = QVBoxLayout(self.binary_widget)
        self.binary_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.binary_icon = QLabel("🔒")
        font = self.binary_icon.font()
        font.setPointSize(48)
        self.binary_icon.setFont(font)
        self.binary_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.binary_layout.addWidget(self.binary_icon)
        
        self.binary_message = QLabel("This file cannot be displayed")
        self.binary_message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = self.binary_message.font()
        font.setBold(True)
        font.setPointSize(14)
        self.binary_message.setFont(font)
        self.binary_layout.addWidget(self.binary_message)
        
        self.binary_info = QLabel("The file format is not supported for direct viewing")
        self.binary_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.binary_info.setWordWrap(True)
        self.binary_layout.addWidget(self.binary_info)
        
        # Details tab
        self.details_tab = QWidget()
        self.details_layout = QFormLayout(self.details_tab)
        self.tabs.addTab(self.details_tab, "Details")
        
        # Action buttons
        self.button_container = QWidget()
        self.button_layout = QHBoxLayout(self.button_container)
        self.button_layout.setContentsMargins(10, 10, 10, 10)
        
        # Status message label (left side)
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #aaa;")
        self.button_layout.addWidget(self.status_label)
        
        # Add spacer to push buttons to the right
        self.button_layout.addStretch()
        
        # Open Externally button (shown for external-viewable types)
        self.open_external_button = QPushButton("Open Externally")
        self.open_external_button.setStyleSheet(StyleManager.get_button_style())
        self.open_external_button.setMinimumWidth(140)
        self.open_external_button.clicked.connect(self._open_externally)
        self.button_layout.addWidget(self.open_external_button)
        
        # Export button (only shown for exportable files)
        self.export_button = QPushButton("Export")
        self.export_button.setStyleSheet(StyleManager.get_button_style("primary"))
        self.export_button.setMinimumWidth(120)
        self.export_button.clicked.connect(self._export_requested)
        self.button_layout.addWidget(self.export_button)
        
        # Close button
        self.close_button = QPushButton("Close")
        self.close_button.setStyleSheet(StyleManager.get_button_style())
        self.close_button.setMinimumWidth(120)
        self.close_button.clicked.connect(self._close_requested)
        self.button_layout.addWidget(self.close_button)
        
        self.layout.addWidget(self.button_container)
    
    def display_content(self, content: bytes, metadata: Dict[str, Any], username: str):
        """Display file content based on its type using enhanced format detection.
        
        Args:
            content: The file content as bytes
            metadata: The file metadata
            username: The current username for watermarking
        """
        try:
            print(f"FileViewer.display_content called for {metadata.get('filename', 'unknown')}")
            print(f"Content size: {len(content)} bytes")
            
            # Clean up any previous content to free memory
            self._cleanup_resources()
            
            # Store for later use
            self.current_content = content
            self.current_metadata = metadata
            self.username = username
            # Use the simple watermarker for view-only file protection
            self.watermarker = SimpleWatermarker(username)
            self.is_view_only = metadata.get("security", {}).get("disable_export", False)
            
            # Detect file format
            filename = metadata.get("filename", "unknown")
            self.current_format_info = self.format_detector.detect_format(filename, content)
            print(f"Format detected: {self.current_format_info}")
            
            # Update UI based on format detection
            self._update_ui_for_format()
            
            # Update details tab
            self._update_details_tab()
            
            # Display content based on format
            print(f"Displaying content - viewable: {self.current_format_info['viewable']}, type: {self.current_format_info['type']}")
            
            if self.current_format_info['viewable']:
                if self.current_format_info['type'] == 'image':
                    print("Calling _display_image_enhanced")
                    self._display_image_enhanced(content)
                elif self.current_format_info['type'] in ['text', 'code', 'data']:
                    print("Calling _display_text_enhanced")
                    self._display_text_enhanced(content)
                elif self.current_format_info['type'] == 'document' and self.current_format_info['format'] == 'pdf':
                    print("Calling _display_pdf_info")
                    self._display_pdf_info()
                else:
                    print("Calling _display_generic_viewable")
                    self._display_generic_viewable()
            else:
                print("Calling _display_non_viewable")
                self._display_non_viewable()
                
        except Exception as e:
            print(f"Unexpected error in display_content: {str(e)}")
            # Show a basic error message if everything fails
            self._display_error(str(e))
    
    def _update_ui_for_format(self):
        """Update UI elements based on detected file format."""
        format_info = self.current_format_info
        
        # Update status label
        confidence_text = "High" if format_info['confidence'] > 80 else "Medium" if format_info['confidence'] > 50 else "Low"
        self.status_label.setText(f"{format_info['display_name']} (Confidence: {confidence_text})")
        
        # Show/hide buttons based on capabilities
        self.export_button.setVisible(not self.is_view_only)
        self.open_external_button.setVisible(format_info.get('external', False) and not self.is_view_only)
        
        # Update button text for external viewer
        if format_info.get('external', False):
            file_type = format_info['type']
            if file_type == 'audio':
                self.open_external_button.setText("Play Audio")
            elif file_type == 'video':
                self.open_external_button.setText("Play Video")
            elif file_type == 'document':
                self.open_external_button.setText("Open Document")
            else:
                self.open_external_button.setText("Open Externally")
    
    def _update_details_tab(self):
        """Update the details tab with file information."""
        # Clear existing details
        for i in reversed(range(self.details_layout.count())):
            self.details_layout.itemAt(i).widget().setParent(None)
        
        metadata = self.current_metadata
        format_info = self.current_format_info
        
        # File information
        self.details_layout.addRow("Filename:", QLabel(metadata.get("filename", "Unknown")))
        self.details_layout.addRow("File Type:", QLabel(format_info['display_name']))
        self.details_layout.addRow("MIME Type:", QLabel(format_info['mime']))
        self.details_layout.addRow("Detection Method:", QLabel(format_info['detection_method'].title()))
        self.details_layout.addRow("Confidence:", QLabel(f"{format_info['confidence']}%"))
        
        # File size
        if self.current_content:
            size_bytes = len(self.current_content)
            if size_bytes < 1024:
                size_text = f"{size_bytes} bytes"
            elif size_bytes < 1024 * 1024:
                size_text = f"{size_bytes / 1024:.1f} KB"
            else:
                size_text = f"{size_bytes / (1024 * 1024):.1f} MB"
            self.details_layout.addRow("File Size:", QLabel(size_text))
        
        # Capabilities
        capabilities = []
        if format_info['viewable']:
            capabilities.append("In-app viewing")
        if format_info.get('external', False):
            capabilities.append("External application")
        if not self.is_view_only:
            capabilities.append("Exportable")
        else:
            capabilities.append("View-only")
        
        self.details_layout.addRow("Capabilities:", QLabel(", ".join(capabilities)))
        
        # Security information
        security = metadata.get("security", {})
        if security.get("disable_export", False):
            security_label = QLabel("View-only (export disabled)")
            security_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
            self.details_layout.addRow("Security:", security_label)
    
    def _display_image_enhanced(self, content: bytes):
        """Display image with enhanced UI."""
        try:
            print(f"_display_image_enhanced called with {len(content)} bytes")
            
            # Check if content is too large (>10MB) to prevent memory issues
            if len(content) > 10 * 1024 * 1024:
                print(f"Large image detected: {len(content) / (1024*1024):.1f} MB")
                self.status_label.setText(f"Large image ({len(content) / (1024*1024):.1f} MB) - may load slowly")
            
            pixmap = QPixmap()
            load_success = False
            
            print("Attempting to load image data into QPixmap...")
            
            # Try to load the image data
            try:
                load_success = pixmap.loadFromData(content)
                print(f"Primary image loading: {'success' if load_success else 'failed'}")
                if load_success:
                    print(f"Pixmap size: {pixmap.width()}x{pixmap.height()}")
            except Exception as e:
                print(f"Primary image loading failed: {str(e)}")
                try:
                    print("Trying alternative QImage approach...")
                    image = QImage()
                    if image.loadFromData(content):
                        pixmap = QPixmap.fromImage(image)
                        load_success = not pixmap.isNull()
                        print(f"Alternative image loading: {'success' if load_success else 'failed'}")
                        if load_success:
                            print(f"Pixmap size: {pixmap.width()}x{pixmap.height()}")
                except Exception as alt_e:
                    print(f"Alternative image loading also failed: {str(alt_e)}")
            
            if load_success:
                print("Calling _display_image with loaded pixmap")
                self._display_image(pixmap)
                print("_display_image completed")
            else:
                print("Image loading failed, showing error")
                self._display_error("Failed to load image data")
        except Exception as e:
            self._display_error(f"Error displaying image: {str(e)}")
    
    def _display_text_enhanced(self, content: bytes):
        """Display text with enhanced formatting and syntax highlighting."""
        try:
            # Try to decode as text
            try:
                text_content = content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    text_content = content.decode('latin-1')
                except UnicodeDecodeError:
                    text_content = content.decode('utf-8', errors='replace')
            
            self.content_type = "text"
            
            # Set up text display
            self.text_widget.setPlainText(text_content)
            
            # Apply syntax highlighting for code files
            if self.current_format_info['type'] == 'code':
                if self.current_format_info['format'] == 'python':
                    highlighter = PythonSyntaxHighlighter(self.text_widget.document())
                # Add more syntax highlighters as needed
            
            self.content_area.setWidget(self.text_widget)
            self.text_widget.setVisible(True)
            
            # Apply watermark if view-only
            if self.is_view_only and self.watermarker:
                self.watermarker.apply_text_watermark(self.text_widget)
            
            # Update status
            line_count = text_content.count('\n') + 1
            char_count = len(text_content)
            self.status_label.setText(f"{line_count} lines, {char_count} characters")
            
        except Exception as e:
            self._display_error(f"Error displaying text: {str(e)}")
    
    def _display_pdf_info(self):
        """Display PDF information and viewing options."""
        self.content_type = "pdf"
        
        # Create PDF info widget
        pdf_widget = QWidget()
        pdf_layout = QVBoxLayout(pdf_widget)
        pdf_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # PDF icon
        pdf_icon = QLabel("📄")
        font = pdf_icon.font()
        font.setPointSize(48)
        pdf_icon.setFont(font)
        pdf_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pdf_layout.addWidget(pdf_icon)
        
        # PDF message
        pdf_message = QLabel("PDF Document")
        pdf_message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = pdf_message.font()
        font.setBold(True)
        font.setPointSize(14)
        pdf_message.setFont(font)
        pdf_layout.addWidget(pdf_message)
        
        # PDF info
        if self.is_view_only:
            info_text = "This PDF is view-only and cannot be exported. You cannot open it with external applications."
        else:
            info_text = "PDFs cannot be displayed directly in the application. Click 'Open Externally' to view it in your default PDF viewer, or 'Export' to save it."
        
        pdf_info = QLabel(info_text)
        pdf_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pdf_info.setWordWrap(True)
        pdf_layout.addWidget(pdf_info)
        
        self.content_area.setWidget(pdf_widget)
    
    def _display_generic_viewable(self):
        """Display generic viewable content."""
        self._display_text_enhanced(self.current_content)
    
    def _display_non_viewable(self):
        """Display message for non-viewable content with helpful instructions."""
        self.content_type = "binary"
        
        format_info = self.current_format_info
        
        # Set appropriate icon based on type
        icon_map = {
            'audio': '🎵',
            'video': '🎬',
            'document': '📄',
            'archive': '📦',
            'executable': '⚙️',
            'database': '🗄️',
            'unknown': '🔒'
        }
        
        self.binary_icon.setText(icon_map.get(format_info['type'], '🔒'))
        self.binary_message.setText(f"{format_info['display_name']} - Cannot Display Directly")
        self.binary_info.setText(format_info['viewer_message'])
        
        # Add view-only notice if applicable
        if self.is_view_only:
            notice = QLabel("This file is marked as view-only and cannot be exported")
            notice.setAlignment(Qt.AlignmentFlag.AlignCenter)
            font = notice.font()
            font.setBold(True)
            notice.setFont(font)
            notice.setStyleSheet("color: #e74c3c;")
            self.binary_layout.addWidget(notice)
        
        self.content_area.setWidget(self.binary_widget)
    
    def _display_error(self, error_message: str):
        """Display error message."""
        error_widget = QWidget()
        error_layout = QVBoxLayout(error_widget)
        error_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        error_icon = QLabel("❌")
        font = error_icon.font()
        font.setPointSize(48)
        error_icon.setFont(font)
        error_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        error_layout.addWidget(error_icon)
        
        error_label = QLabel("Error Displaying File")
        error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = error_label.font()
        font.setBold(True)
        font.setPointSize(14)
        error_label.setFont(font)
        error_layout.addWidget(error_label)
        
        error_details = QLabel(error_message)
        error_details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        error_details.setWordWrap(True)
        error_details.setStyleSheet("color: #e74c3c;")
        error_layout.addWidget(error_details)
        
        self.content_area.setWidget(error_widget)
    
    def _open_externally(self):
        """Open file with external application."""
        if not self.current_content or not self.current_format_info:
            QMessageBox.warning(self, "Error", "No file loaded to open externally.")
            return
        
        if self.is_view_only:
            QMessageBox.warning(self, "Restricted", "This file is view-only and cannot be opened with external applications.")
            return
        
        try:
            # Get appropriate file extension
            filename = self.current_metadata.get("filename", "temp_file")
            _, ext = os.path.splitext(filename)
            if not ext:
                # Try to determine extension from format
                format_to_ext = {
                    'mp3': '.mp3', 'wav': '.wav', 'flac': '.flac', 'ogg': '.ogg',
                    'mp4': '.mp4', 'avi': '.avi', 'mkv': '.mkv', 'mov': '.mov',
                    'pdf': '.pdf', 'doc': '.doc', 'docx': '.docx',
                    'jpeg': '.jpg', 'png': '.png', 'gif': '.gif'
                }
                ext = format_to_ext.get(self.current_format_info['format'], '')
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as temp_file:
                temp_file.write(self.current_content)
                temp_path = temp_file.name
            
            # Track for cleanup
            self.temp_files.append(temp_path)
            
            # Launch external viewer in thread
            self.external_thread = ExternalViewerThread(temp_path, self.current_format_info)
            self.external_thread.finished_signal.connect(self._on_external_viewer_finished)
            self.external_thread.start()
            
            # Show progress
            self.status_label.setText("Opening with external application...")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open file externally: {str(e)}")
    
    @pyqtSlot(bool, str)
    def _on_external_viewer_finished(self, success: bool, message: str):
        """Handle external viewer completion."""
        if success:
            self.status_label.setText(message)
        else:
            self.status_label.setText("Failed to open externally")
            QMessageBox.warning(self, "External Viewer Error", message)
    
    def set_export_handler(self, handler: Callable):
        """Set the export handler function."""
        self.export_handler = handler
    
    def _export_requested(self):
        """Handle export request."""
        if self.export_handler:
            self.export_handler()
        else:
            self.export_requested.emit()
    
    def _close_requested(self):
        """Handle close request."""
        self._cleanup_resources()
        self.close_requested.emit()
    
    def _cleanup_resources(self):
        """Clean up resources and temporary files."""
        # Clean up temporary files
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"Failed to clean up temporary file {temp_file}: {e}")
        self.temp_files.clear()
        
        # Clean up large objects
        self.current_content = None
        
        # Force garbage collection
        import gc
        gc.collect()
    
    def closeEvent(self, event):
        """Handle widget close event."""
        self._cleanup_resources()
        super().closeEvent(event)
    
    def __del__(self):
        """Destructor to ensure cleanup."""
        try:
            self._cleanup_resources()
        except:
            pass
    
    def _display_image(self, pixmap: QPixmap):
        """Display image content using the existing image display logic."""
        try:
            print(f"_display_image called with pixmap: {pixmap.width()}x{pixmap.height()}")
            
            # Verify the pixmap is valid
            if pixmap.isNull():
                print("Pixmap is null, showing error")
                self._display_error("Invalid image data")
                return
            
            # Check for extremely large images that could cause memory issues
            pixel_count = pixmap.width() * pixmap.height()
            if pixel_count > 50000000:  # 50 million pixels
                print(f"Image too large: {pixel_count} pixels")
                self._display_error(f"Image too large to display safely ({pixmap.width()}x{pixmap.height()})")
                return
                
            # Check if image dimensions are too large
            if pixmap.width() > 8000 or pixmap.height() > 8000:
                print(f"Image dimensions too large: {pixmap.width()}x{pixmap.height()}")
                # Pre-scale very large images to prevent memory issues
                try:
                    max_dimension = 4000
                    if pixmap.width() > pixmap.height():
                        pixmap = pixmap.scaled(max_dimension, 
                                              int(max_dimension * pixmap.height() / pixmap.width()), 
                                              Qt.KeepAspectRatio, 
                                              Qt.FastTransformation)
                    else:
                        pixmap = pixmap.scaled(int(max_dimension * pixmap.width() / pixmap.height()),
                                              max_dimension, 
                                              Qt.KeepAspectRatio, 
                                              Qt.FastTransformation)
                except Exception as e:
                    print(f"Error pre-scaling large image: {str(e)}")
                    # Continue with original if pre-scaling fails
            
            self.content_type = "image"
            
            # Clear any previous notices from the layout
            for i in reversed(range(self.image_layout.count())):
                item = self.image_layout.itemAt(i)
                if item.widget() != self.image_label:
                    item.widget().deleteLater()
            
            # Scale the image to fit the view while maintaining aspect ratio
            try:
                # Get the current size of the viewport for better scaling
                viewport_width = self.content_area.viewport().width() or 800
                viewport_height = self.content_area.viewport().height() or 600
                
                # Scale to fit viewport with some margin
                target_width = max(100, min(viewport_width - 20, 1200))
                target_height = max(100, min(viewport_height - 20, 800))
                
                scaled_pixmap = pixmap.scaled(
                    target_width, target_height, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                
                # Force garbage collection of the original pixmap if it's very large
                if pixmap.width() * pixmap.height() > 4000000:  # More than 4 million pixels
                    pixmap = None  # Help garbage collection
                    import gc
                    gc.collect()  # Force garbage collection
                    
            except Exception as e:
                print(f"Error scaling image: {str(e)}")
                # If scaling fails, use original
                scaled_pixmap = pixmap
            
            # Apply watermark if view-only
            try:
                final_pixmap = None
                if self.is_view_only and self.watermarker:
                    try:
                        watermarked_pixmap = self.watermarker.apply_image_watermark(
                            self.image_label, scaled_pixmap)
                        final_pixmap = watermarked_pixmap
                    except Exception as e:
                        print(f"Error applying watermark: {str(e)}")
                        # If watermarking fails, use the scaled pixmap
                        final_pixmap = scaled_pixmap
                else:
                    final_pixmap = scaled_pixmap
                
                # Verify the final pixmap is valid before setting it
                if final_pixmap and not final_pixmap.isNull():
                    # Set the pixmap in a safe way
                    try:
                        print(f"Setting pixmap on image_label: {final_pixmap.width()}x{final_pixmap.height()}")
                        self.image_label.setPixmap(final_pixmap)
                        print(f"Image label size after setting pixmap: {self.image_label.size()}")
                        print(f"Image label pixmap size: {self.image_label.pixmap().size() if self.image_label.pixmap() else 'None'}")
                        
                        # Update status with image dimensions
                        self.status_label.setText(f"Image: {final_pixmap.width()}x{final_pixmap.height()} pixels")
                    except Exception as set_error:
                        print(f"Error setting pixmap to label: {str(set_error)}")
                        # Last resort - create a new small pixmap
                        fallback_pixmap = QPixmap(400, 300)
                        fallback_pixmap.fill(QColor(240, 240, 240))
                        self.image_label.setPixmap(fallback_pixmap)
                        self.status_label.setText("Error displaying image - using placeholder")
                else:
                    print("Final pixmap is null or invalid")
                    self._display_error("Invalid image data")
                    return
            except Exception as e:
                print(f"Unexpected error in pixmap handling: {str(e)}")
                self._display_error(str(e))
                return
            
            # Add view-only notice if applicable
            if self.is_view_only:
                notice = QLabel("This image is view-only and cannot be exported")
                notice.setAlignment(Qt.AlignmentFlag.AlignCenter)
                font = notice.font()
                font.setBold(True)
                notice.setFont(font)
                notice.setStyleSheet("color: #e74c3c;")
                self.image_layout.addWidget(notice)
            
            print("Setting image_container as content area widget")
            self.content_area.setWidget(self.image_container)
            print("Content area widget set successfully")
        except Exception as e:
            print(f"Error displaying image: {str(e)}")
            self._display_error(f"Error displaying image: {str(e)}")
