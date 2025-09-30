import asyncio
import sys
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QTextEdit, QScrollArea, QFrame, QGroupBox,
    QDialog, QApplication, QMessageBox, QListWidget, QListWidgetItem,
    QSplitter, QTabWidget
)
from PySide6.QtCore import (
    QThread, Signal as pyqtSignal, QObject, QTimer, Qt, QMutex, QWaitCondition,
    QRunnable, QThreadPool
)
from PySide6.QtGui import QFont, QPalette, QColor

from ..file_manager.async_file_manager import (
    AsyncFileManager, FileOperationProgress, MemoryMonitor
)
from ..crypto.async_encryption import AsyncEncryptionManager, PerformanceMetrics
from .styles import StyleManager


@dataclass
class UIPerformanceMetrics:
    """UI-specific performance metrics."""
    update_frequency: float  # Updates per second
    render_time: float      # Time to render updates
    memory_usage: int       # UI memory usage
    active_threads: int     # Number of active background threads
    timestamp: datetime


class AsyncOperationSignals(QObject):
    """Signals for async operation communication with GUI."""
    
    # Progress signals
    progress_updated = pyqtSignal(str, dict)  # operation_id, progress_data
    operation_started = pyqtSignal(str, str)  # operation_id, operation_type
    operation_completed = pyqtSignal(str, dict)  # operation_id, result_data
    operation_failed = pyqtSignal(str, str)  # operation_id, error_message
    operation_cancelled = pyqtSignal(str)  # operation_id
    
    # Performance signals
    performance_update = pyqtSignal(dict)  # performance_metrics
    memory_warning = pyqtSignal(dict)      # memory_info
    
    # UI feedback signals
    status_message = pyqtSignal(str, int)  # message, timeout_ms


class AsyncOperationWorker(QThread):
    """Worker thread for executing async operations without blocking UI."""
    
    def __init__(self, async_func, *args, **kwargs):
        """Initialize worker with async function and arguments.
        
        Args:
            async_func: The async function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
        """
        super().__init__()
        self.async_func = async_func
        self.args = args
        self.kwargs = kwargs
        self.signals = AsyncOperationSignals()
        self.result = None
        self.error = None
        self.cancelled = False
        
        # Operation tracking
        self.operation_id = kwargs.get('operation_id', f"op_{int(time.time())}")
        self.start_time = None
        
    def run(self):
        """Run the async operation in a separate event loop."""
        self.start_time = datetime.now()
        
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Emit start signal
            self.signals.operation_started.emit(
                self.operation_id, 
                self.async_func.__name__
            )
            
            # Run the async function
            self.result = loop.run_until_complete(
                self.async_func(*self.args, **self.kwargs)
            )
            
            # Emit completion signal
            if not self.cancelled:
                result_data = {
                    'result': self.result,
                    'duration': (datetime.now() - self.start_time).total_seconds(),
                    'operation_id': self.operation_id
                }
                self.signals.operation_completed.emit(self.operation_id, result_data)
            
        except Exception as e:
            self.error = str(e)
            if not self.cancelled:
                self.signals.operation_failed.emit(self.operation_id, str(e))
        
        finally:
            # Clean up event loop
            if 'loop' in locals():
                loop.close()
    
    def cancel(self):
        """Cancel the operation."""
        self.cancelled = True
        self.signals.operation_cancelled.emit(self.operation_id)
        if self.isRunning():
            self.terminate()
            self.wait(5000)  # Wait up to 5 seconds for thread to finish


class ProgressTracker(QWidget):
    """Widget for tracking and displaying operation progress."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.active_operations = {}
        self.setup_ui()
        
        # Update timer for real-time display
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(100)  # Update every 100ms
        
        # Performance tracking
        self.ui_metrics = []
        self.last_update_time = time.time()
        self.update_count = 0
    
    def setup_ui(self):
        """Set up the progress tracker UI."""
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        self.header_label = QLabel("Active Operations")
        self.header_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.header_label.setStyleSheet("color: #ffffff; margin-bottom: 10px;")
        self.layout.addWidget(self.header_label)
        
        # Scroll area for operations
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setMinimumHeight(200)
        self.scroll_widget = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_widget)
        self.scroll_area.setWidget(self.scroll_widget)
        self.layout.addWidget(self.scroll_area)
        
        # Summary info
        self.summary_label = QLabel("No active operations")
        self.summary_label.setStyleSheet("color: #888888; font-style: italic;")
        self.layout.addWidget(self.summary_label)
    
    def add_operation(self, operation_id: str, operation_type: str, 
                     file_path: str = "", total_bytes: int = 0):
        """Add a new operation to track."""
        if operation_id not in self.active_operations:
            progress_widget = OperationProgressWidget(
                operation_id, operation_type, file_path, total_bytes
            )
            self.active_operations[operation_id] = progress_widget
            self.scroll_layout.addWidget(progress_widget)
            self.update_summary()
    
    def update_operation_progress(self, operation_id: str, progress_data: dict):
        """Update progress for an operation."""
        if operation_id in self.active_operations:
            self.active_operations[operation_id].update_progress(progress_data)
        
        # Track UI performance
        self.update_count += 1
        current_time = time.time()
        if current_time - self.last_update_time >= 1.0:  # Every second
            frequency = self.update_count / (current_time - self.last_update_time)
            
            ui_metric = UIPerformanceMetrics(
                update_frequency=frequency,
                render_time=0,  # TODO: Measure render time
                memory_usage=0,  # TODO: Measure UI memory
                active_threads=len(self.active_operations),
                timestamp=datetime.now()
            )
            
            self.ui_metrics.append(ui_metric)
            if len(self.ui_metrics) > 100:  # Keep last 100 metrics
                self.ui_metrics = self.ui_metrics[-100:]
            
            self.last_update_time = current_time
            self.update_count = 0
    
    def complete_operation(self, operation_id: str, success: bool = True, 
                         error_message: str = None):
        """Mark an operation as completed."""
        if operation_id in self.active_operations:
            widget = self.active_operations[operation_id]
            widget.mark_completed(success, error_message)
            
            # Remove after 5 seconds
            QTimer.singleShot(5000, lambda: self.remove_operation(operation_id))
    
    def remove_operation(self, operation_id: str):
        """Remove an operation from tracking."""
        if operation_id in self.active_operations:
            widget = self.active_operations.pop(operation_id)
            self.scroll_layout.removeWidget(widget)
            widget.deleteLater()
            self.update_summary()
    
    def cancel_operation(self, operation_id: str):
        """Cancel an operation."""
        if operation_id in self.active_operations:
            self.active_operations[operation_id].mark_cancelled()
    
    def update_display(self):
        """Update the display with latest information."""
        # This is called regularly to refresh the UI
        pass
    
    def update_summary(self):
        """Update the summary information."""
        count = len(self.active_operations)
        if count == 0:
            self.summary_label.setText("No active operations")
        elif count == 1:
            self.summary_label.setText("1 active operation")
        else:
            self.summary_label.setText(f"{count} active operations")
    
    def get_ui_performance_metrics(self) -> Dict[str, Any]:
        """Get UI performance metrics."""
        if not self.ui_metrics:
            return {'no_metrics': True}
        
        recent_metrics = self.ui_metrics[-10:]  # Last 10 metrics
        avg_frequency = sum(m.update_frequency for m in recent_metrics) / len(recent_metrics)
        
        return {
            'average_update_frequency': avg_frequency,
            'active_operations_count': len(self.active_operations),
            'total_ui_updates': sum(len(self.ui_metrics), 0),
            'metrics_collected': len(self.ui_metrics)
        }


class OperationProgressWidget(QFrame):
    """Widget displaying progress for a single operation."""
    
    def __init__(self, operation_id: str, operation_type: str, 
                 file_path: str, total_bytes: int):
        super().__init__()
        self.operation_id = operation_id
        self.operation_type = operation_type
        self.file_path = file_path
        self.total_bytes = total_bytes
        self.start_time = datetime.now()
        self.processed_bytes = 0
        self.status = "in_progress"
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the progress widget UI."""
        self.setFrameStyle(QFrame.Box)
        self.setStyleSheet("""
            QFrame {
                border: 1px solid #444444;
                border-radius: 5px;
                margin: 2px;
                padding: 5px;
                background-color: #2b2b2b;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Operation info
        info_layout = QHBoxLayout()
        
        self.operation_label = QLabel(f"{self.operation_type.title()}")
        self.operation_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        self.operation_label.setStyleSheet("color: #ffffff;")
        info_layout.addWidget(self.operation_label)
        
        info_layout.addStretch()
        
        self.status_label = QLabel("Starting...")
        self.status_label.setStyleSheet("color: #888888;")
        info_layout.addWidget(self.status_label)
        
        layout.addLayout(info_layout)
        
        # File info
        if self.file_path:
            file_name = self.file_path.split('/')[-1].split('\\')[-1]
            self.file_label = QLabel(f"File: {file_name}")
            self.file_label.setStyleSheet("color: #cccccc; font-size: 9px;")
            layout.addWidget(self.file_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                background-color: #333333;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 2px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Details layout
        details_layout = QHBoxLayout()
        
        self.bytes_label = QLabel("0 B / 0 B")
        self.bytes_label.setStyleSheet("color: #888888; font-size: 9px;")
        details_layout.addWidget(self.bytes_label)
        
        details_layout.addStretch()
        
        self.speed_label = QLabel("0 B/s")
        self.speed_label.setStyleSheet("color: #888888; font-size: 9px;")
        details_layout.addWidget(self.speed_label)
        
        self.eta_label = QLabel("")
        self.eta_label.setStyleSheet("color: #888888; font-size: 9px;")
        details_layout.addWidget(self.eta_label)
        
        layout.addLayout(details_layout)
        
        # Cancel button (initially hidden)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setMaximumWidth(60)
        self.cancel_button.setMaximumHeight(25)
        self.cancel_button.clicked.connect(self.cancel_clicked)
        self.cancel_button.setStyleSheet(StyleManager.get_button_style("warning"))
        self.cancel_button.hide()  # Show only when needed
        
        # Add cancel button to details layout
        details_layout.addWidget(self.cancel_button)
    
    def update_progress(self, progress_data: dict):
        """Update the progress display."""
        self.processed_bytes = progress_data.get('bytes_processed', 0)
        total_bytes = progress_data.get('total_bytes', self.total_bytes)
        
        # Update progress bar
        if total_bytes > 0:
            percentage = min(100, int((self.processed_bytes / total_bytes) * 100))
            self.progress_bar.setValue(percentage)
        
        # Update status
        status = progress_data.get('status', 'in_progress')
        if status == 'in_progress':
            self.status_label.setText("Processing...")
            self.status_label.setStyleSheet("color: #0078d4;")
            if not self.cancel_button.isVisible():
                self.cancel_button.show()
        
        # Update byte counts
        processed_str = self.format_bytes(self.processed_bytes)
        total_str = self.format_bytes(total_bytes) if total_bytes > 0 else "Unknown"
        self.bytes_label.setText(f"{processed_str} / {total_str}")
        
        # Calculate and display speed
        elapsed_time = (datetime.now() - self.start_time).total_seconds()
        if elapsed_time > 0:
            speed = self.processed_bytes / elapsed_time
            speed_str = self.format_bytes(speed) + "/s"
            self.speed_label.setText(speed_str)
            
            # Calculate ETA
            if total_bytes > 0 and speed > 0:
                remaining_bytes = total_bytes - self.processed_bytes
                eta_seconds = remaining_bytes / speed
                eta_str = self.format_time(eta_seconds)
                self.eta_label.setText(f"ETA: {eta_str}")
    
    def mark_completed(self, success: bool = True, error_message: str = None):
        """Mark the operation as completed."""
        self.status = "completed" if success else "failed"
        
        if success:
            self.status_label.setText("Completed")
            self.status_label.setStyleSheet("color: #00aa00;")
            self.progress_bar.setValue(100)
        else:
            self.status_label.setText("Failed")
            self.status_label.setStyleSheet("color: #aa0000;")
            if error_message:
                self.speed_label.setText(f"Error: {error_message[:50]}...")
        
        self.cancel_button.hide()
        
        # Update styling to indicate completion
        if success:
            self.setStyleSheet(self.styleSheet() + """
                QFrame { border-color: #00aa00; }
            """)
        else:
            self.setStyleSheet(self.styleSheet() + """
                QFrame { border-color: #aa0000; }
            """)
    
    def mark_cancelled(self):
        """Mark the operation as cancelled."""
        self.status = "cancelled"
        self.status_label.setText("Cancelled")
        self.status_label.setStyleSheet("color: #ff8800;")
        self.cancel_button.hide()
        
        self.setStyleSheet(self.styleSheet() + """
            QFrame { border-color: #ff8800; }
        """)
    
    def cancel_clicked(self):
        """Handle cancel button click."""
        # Emit signal to parent or operation manager
        # This will be connected to the actual cancellation logic
        self.cancel_button.setEnabled(False)
        self.cancel_button.setText("Cancelling...")
    
    @staticmethod
    def format_bytes(bytes_value: float) -> str:
        """Format bytes into human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f} TB"
    
    @staticmethod
    def format_time(seconds: float) -> str:
        """Format seconds into human-readable time."""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"


class PerformanceMonitorWidget(QWidget):
    """Widget for displaying real-time performance metrics."""
    
    def __init__(self, async_file_manager: AsyncFileManager = None, parent=None):
        super().__init__(parent)
        self.async_file_manager = async_file_manager
        self.setup_ui()
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_metrics)
        self.update_timer.start(1000)  # Update every second
    
    def setup_ui(self):
        """Set up the performance monitor UI."""
        layout = QVBoxLayout(self)
        
    # Title
    title = QLabel("Performance Monitor")
    title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
    title.setStyleSheet("color: #ffffff; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Metrics display
        self.metrics_text = QTextEdit()
        self.metrics_text.setMaximumHeight(200)
        self.metrics_text.setReadOnly(True)
        self.metrics_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444444;
                border-radius: 5px;
                font-family: 'Courier New', monospace;
                font-size: 9px;
            }
        """)
        layout.addWidget(self.metrics_text)
    
    def update_metrics(self):
        """Update the performance metrics display."""
        if not self.async_file_manager:
            return
        
        try:
            # Get performance metrics
            metrics = self.async_file_manager.get_performance_metrics()
            
            # Format metrics for display
            lines = [
                f"=== Performance Metrics ({datetime.now().strftime('%H:%M:%S')}) ===",
                f"Active Operations: {metrics.get('active_operations', 0)}",
                f"Max Workers: {metrics.get('max_workers', 0)}",
                f"Async File Ops: {metrics.get('async_file_operations', 0)}",
                ""
            ]
            
            # Memory usage
            memory = metrics.get('memory_usage', {})
            if 'error' not in memory:
                rss_mb = memory.get('rss', 0) / (1024 * 1024)
                vms_mb = memory.get('vms', 0) / (1024 * 1024)
                percent = memory.get('percent', 0)
                max_mb = memory.get('max_allowed', 0) / (1024 * 1024)
                
                lines.extend([
                    f"=== Memory Usage ===",
                    f"Physical: {rss_mb:.1f} MB ({percent:.1f}%)",
                    f"Virtual: {vms_mb:.1f} MB",
                    f"Max Allowed: {max_mb:.1f} MB",
                    ""
                ])
            
            # File operations stats
            file_ops = metrics.get('file_operations', {})
            if file_ops:
                total_mb = file_ops.get('total_bytes_processed', 0) / (1024 * 1024)
                total_time = file_ops.get('total_time', 0)
                avg_throughput = file_ops.get('average_throughput', 0) / (1024 * 1024)
                
                lines.extend([
                    f"=== File Operations ===",
                    f"Total Processed: {total_mb:.1f} MB",
                    f"Total Time: {total_time:.1f}s",
                    f"Avg Throughput: {avg_throughput:.1f} MB/s",
                    f"Operations: {file_ops.get('operations_count', 0)}",
                    ""
                ])
            
            # Encryption performance
            encryption = metrics.get('encryption_performance', {})
            if encryption.get('total_operations', 0) > 0:
                enc_mb = encryption.get('total_bytes_processed', 0) / (1024 * 1024)
                enc_throughput = encryption.get('overall_avg_throughput', 0) / (1024 * 1024)
                
                lines.extend([
                    f"=== Encryption Performance ===",
                    f"Total Encrypted: {enc_mb:.1f} MB",
                    f"Avg Throughput: {enc_throughput:.1f} MB/s",
                    f"Operations: {encryption.get('total_operations', 0)}",
                    ""
                ])
            
            # Set the text
            self.metrics_text.setPlainText('\n'.join(lines))
            
            # Auto-scroll to bottom
            cursor = self.metrics_text.textCursor()
            cursor.movePosition(cursor.End)
            self.metrics_text.setTextCursor(cursor)
            
        except Exception as e:
            self.metrics_text.setPlainText(f"Error updating metrics: {str(e)}")


class AsyncFileOperationDialog(QDialog):
    """Dialog for performing async file operations with progress tracking."""
    
    def __init__(self, async_file_manager: AsyncFileManager, parent=None):
        super().__init__(parent)
        self.async_file_manager = async_file_manager
        self.active_workers = {}
        self.setup_ui()
        
        self.setWindowTitle("File Operations")
        self.setMinimumSize(600, 400)
        
        # Apply dark theme
        StyleManager.apply_theme("dark")
    
    def setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)
        
        # Create tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Progress tracking tab
        progress_tab = QWidget()
        progress_layout = QVBoxLayout(progress_tab)
        
        self.progress_tracker = ProgressTracker()
        progress_layout.addWidget(self.progress_tracker)
        
        tabs.addTab(progress_tab, "Operations")
        
        # Performance monitoring tab
        performance_tab = QWidget()
        performance_layout = QVBoxLayout(performance_tab)
        
        self.performance_monitor = PerformanceMonitorWidget(self.async_file_manager)
        performance_layout.addWidget(self.performance_monitor)
        
        tabs.addTab(performance_tab, "Performance")
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        self.close_button.setStyleSheet(StyleManager.get_button_style())
        button_layout.addStretch()
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
    
    async def create_file_async(self, content: bytes, filename: str, 
                              password: str, security_settings: dict) -> str:
        """Create a file asynchronously with progress tracking."""
        
        # Progress callback
        async def progress_callback(progress_data):
            # This will be called from the worker thread
            pass
        
        # Create worker
        worker = AsyncOperationWorker(
            self.async_file_manager.create_secure_file_async,
            content, filename, password, security_settings,
            progress_callback=progress_callback
        )
        
        # Connect signals
        worker.signals.operation_started.connect(
            lambda op_id, op_type: self.progress_tracker.add_operation(
                op_id, op_type, filename, len(content)
            )
        )
        
        worker.signals.progress_updated.connect(
            self.progress_tracker.update_operation_progress
        )
        
        worker.signals.operation_completed.connect(
            lambda op_id, result: self.progress_tracker.complete_operation(op_id, True)
        )
        
        worker.signals.operation_failed.connect(
            lambda op_id, error: self.progress_tracker.complete_operation(
                op_id, False, error
            )
        )
        
        # Start worker
        operation_id = worker.operation_id
        self.active_workers[operation_id] = worker
        worker.start()
        
        return operation_id
    
    async def access_file_async(self, file_id: str, password: str) -> str:
        """Access a file asynchronously with progress tracking."""
        
        # Progress callback
        async def progress_callback(progress_data):
            pass
        
        # Create worker
        worker = AsyncOperationWorker(
            self.async_file_manager.access_file_async,
            file_id, password,
            progress_callback=progress_callback
        )
        
        # Connect signals (similar to create_file_async)
        worker.signals.operation_started.connect(
            lambda op_id, op_type: self.progress_tracker.add_operation(
                op_id, op_type, file_id
            )
        )
        
        worker.signals.progress_updated.connect(
            self.progress_tracker.update_operation_progress
        )
        
        worker.signals.operation_completed.connect(
            lambda op_id, result: self.progress_tracker.complete_operation(op_id, True)
        )
        
        worker.signals.operation_failed.connect(
            lambda op_id, error: self.progress_tracker.complete_operation(
                op_id, False, error
            )
        )
        
        # Start worker
        operation_id = worker.operation_id
        self.active_workers[operation_id] = worker
        worker.start()
        
        return operation_id
    
    def cancel_operation(self, operation_id: str):
        """Cancel an active operation."""
        if operation_id in self.active_workers:
            worker = self.active_workers[operation_id]
            worker.cancel()
            self.progress_tracker.cancel_operation(operation_id)
            del self.active_workers[operation_id]
    
    def closeEvent(self, event):
        """Handle dialog close event."""
        # Cancel all active operations
        for operation_id in list(self.active_workers.keys()):
            self.cancel_operation(operation_id)
        
        super().closeEvent(event)


# Integration helper functions

def integrate_async_file_operations(main_window, async_file_manager: AsyncFileManager):
    """Integrate async file operations into the main window.
    
    This function adds async operation capabilities to the existing main window
    by replacing synchronous operations with async equivalents.
    """
    
    # Store reference to async file manager
    main_window.async_file_manager = async_file_manager
    
    # Create async operation dialog
    main_window.async_dialog = AsyncFileOperationDialog(async_file_manager, main_window)
    
    # Replace existing file operation methods
    original_add_file = main_window._add_file
    
    def async_add_file():
        """Async version of add file operation."""
        main_window.async_dialog.show()
        # The actual file adding will be handled by the dialog
    
    # Connect the new async method
    main_window._add_file_async = async_add_file
    
    # Add menu item for async operations
    if hasattr(main_window, 'menuBar'):
        async_menu = main_window.menuBar().addMenu("Async Operations")
        
        show_operations_action = async_menu.addAction("Show Operations")
        show_operations_action.triggered.connect(
            lambda: main_window.async_dialog.show()
        )
        
        performance_action = async_menu.addAction("Performance Monitor")
        performance_action.triggered.connect(
            lambda: main_window.async_dialog.show() and 
                   main_window.async_dialog.tabs.setCurrentIndex(1)
        )


def create_performance_dashboard(async_file_manager: AsyncFileManager, 
                               parent=None) -> QWidget:
    """Create a standalone performance dashboard widget."""
    
    dashboard = QWidget(parent)
    layout = QVBoxLayout(dashboard)
    
    # Title
    title = QLabel("BAR Performance Dashboard")
    title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
    title.setStyleSheet("color: #ffffff; margin-bottom: 20px;")
    title.setAlignment(Qt.AlignmentFlag.AlignCenter)
    layout.addWidget(title)
    
    # Create splitter for layout
    splitter = QSplitter(Qt.Orientation.Horizontal)
    
    # Progress tracker
    progress_tracker = ProgressTracker()
    progress_group = QGroupBox("Active Operations")
    progress_group.setLayout(QVBoxLayout())
    progress_group.layout().addWidget(progress_tracker)
    splitter.addWidget(progress_group)
    
    # Performance monitor
    performance_monitor = PerformanceMonitorWidget(async_file_manager)
    performance_group = QGroupBox("Performance Metrics")
    performance_group.setLayout(QVBoxLayout())
    performance_group.layout().addWidget(performance_monitor)
    splitter.addWidget(performance_group)
    
    layout.addWidget(splitter)
    
    # Apply styling
    dashboard.setStyleSheet("""
        QGroupBox {
            font-weight: bold;
            border: 2px solid #444444;
            border-radius: 5px;
            margin: 5px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 10px 0 10px;
            color: #ffffff;
        }
    """)
    
    return dashboard