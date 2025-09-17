#!/usr/bin/env python3
"""
Comprehensive demonstration of async performance optimizations in BAR.

This example shows how to integrate and use all the async components:
- AsyncEncryptionManager with streaming support
- AsyncFileManager with thread pool execution
- AsyncFileScanner with concurrent device scanning
- PerformanceMonitor with automatic optimization
- Async GUI components with progress tracking

Author: Rolan Lobo (RNR)
Version: 2.0.0
Project: BAR - Burn After Reading Security Suite
"""

import asyncio
import os
import sys
import logging
import time
from pathlib import Path
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from src.crypto.async_encryption import AsyncEncryptionManager, StreamingConfig
from src.file_manager.async_file_manager import AsyncFileManager
from src.file_manager.async_file_scanner import AsyncFileScanner
from src.performance.performance_monitor import PerformanceMonitor
from src.gui.async_components import create_performance_dashboard


def setup_logging():
    """Set up logging for the demo."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('async_performance_demo.log')
        ]
    )
    return logging.getLogger("AsyncPerformanceDemo")


async def demo_async_encryption():
    """Demonstrate async encryption with streaming support."""
    logger = logging.getLogger("AsyncEncryption")
    logger.info("🔐 Starting async encryption demonstration...")
    
    async with AsyncEncryptionManager(max_workers=4) as enc_manager:
        # Test data of various sizes
        test_files = [
            ("small_file.txt", b"Small file content for testing" * 100),  # ~3KB
            ("medium_file.txt", b"Medium file content for testing" * 10000),  # ~300KB  
            ("large_file.txt", b"Large file content for testing" * 1000000)  # ~30MB
        ]
        
        results = []
        
        for filename, content in test_files:
            logger.info(f"Processing {filename} ({len(content):,} bytes)")
            
            # Test streaming encryption vs regular encryption
            password = "test_password_123"
            
            start_time = time.time()
            
            if len(content) > StreamingConfig.MEDIUM_FILE_CHUNK_SIZE:
                # Use streaming for large files
                logger.info(f"Using streaming encryption for {filename}")
                
                # Create async iterator for content
                async def content_stream():
                    chunk_size = StreamingConfig.get_optimal_chunk_size(
                        len(content), StreamingConfig.MAX_MEMORY_USAGE
                    )
                    for i in range(0, len(content), chunk_size):
                        chunk = content[i:i+chunk_size]
                        yield chunk
                
                # Collect encrypted chunks
                encrypted_chunks = []
                async for encrypted_chunk in enc_manager.encrypt_stream_async(
                    content_stream(), password
                ):
                    encrypted_chunks.append(encrypted_chunk)
                
                # For demo, we'd normally save these chunks
                total_encrypted_size = sum(len(str(chunk)) for chunk in encrypted_chunks)
                
            else:
                # Use regular encryption for smaller files
                salt = enc_manager.generate_salt()
                key = await enc_manager.derive_key_async(password, salt)
                
                # Encrypt in thread pool
                loop = asyncio.get_event_loop()
                encrypted_data = await loop.run_in_executor(
                    enc_manager.executor,
                    lambda: enc_manager.encrypt_data(content, key)
                )
                total_encrypted_size = len(encrypted_data['ciphertext'])
            
            duration = time.time() - start_time
            throughput = len(content) / duration if duration > 0 else 0
            
            result = {
                'filename': filename,
                'original_size': len(content),
                'encrypted_size': total_encrypted_size,
                'duration': duration,
                'throughput_mb_s': throughput / (1024 * 1024),
                'compression_ratio': total_encrypted_size / len(content)
            }
            results.append(result)
            
            logger.info(f"✅ {filename}: {throughput/1024/1024:.2f} MB/s, "
                       f"{duration:.2f}s, ratio: {result['compression_ratio']:.2f}")
        
        # Display performance metrics
        perf_metrics = enc_manager.get_performance_metrics()
        logger.info(f"📊 Encryption performance: {perf_metrics['total_operations']} operations, "
                   f"avg {perf_metrics['overall_avg_throughput']/1024/1024:.2f} MB/s")
        
        return results


async def demo_async_file_manager():
    """Demonstrate async file manager with progress tracking."""
    logger = logging.getLogger("AsyncFileManager")
    logger.info("📁 Starting async file manager demonstration...")
    
    # Create temporary directory for demo
    demo_dir = Path.cwd() / "demo_files"
    demo_dir.mkdir(exist_ok=True)
    
    async with AsyncFileManager(
        str(demo_dir), 
        max_workers=6, 
        max_memory_mb=512
    ) as file_manager:
        
        # Create test files with different security settings
        test_files = [
            {
                'filename': 'confidential_doc.txt',
                'content': b'Confidential document content' * 1000,
                'password': 'secure_pass_123',
                'security_settings': {
                    'max_access_count': 5,
                    'disable_export': True,
                    'expiration_time': None
                }
            },
            {
                'filename': 'temporary_note.txt', 
                'content': b'Temporary note that will expire' * 500,
                'password': 'temp_pass_456',
                'security_settings': {
                    'max_access_count': 3,
                    'expiration_time': (datetime.now().timestamp() + 3600),  # 1 hour
                    'deadman_switch': 1  # 1 day
                }
            },
            {
                'filename': 'large_dataset.bin',
                'content': os.urandom(5 * 1024 * 1024),  # 5MB random data
                'password': 'data_pass_789',
                'security_settings': {
                    'max_access_count': 10,
                    'disable_export': False
                }
            }
        ]
        
        created_files = []
        
        # Progress tracking callback
        async def progress_callback(progress_data):
            logger.debug(f"Progress: {progress_data.get('bytes_processed', 0):,} / "
                        f"{progress_data.get('total_bytes', 0):,} bytes")
        
        # Create files concurrently
        create_tasks = []
        for file_info in test_files:
            task = file_manager.create_secure_file_async(
                content=file_info['content'],
                filename=file_info['filename'],
                password=file_info['password'],
                security_settings=file_info['security_settings'],
                progress_callback=progress_callback
            )
            create_tasks.append(task)
        
        # Wait for all files to be created
        start_time = time.time()
        results = await asyncio.gather(*create_tasks)
        duration = time.time() - start_time
        
        for i, (file_id, operation_id) in enumerate(results):
            created_files.append((file_id, test_files[i]['filename']))
            logger.info(f"✅ Created {test_files[i]['filename']} with ID: {file_id}")
        
        logger.info(f"📊 Created {len(created_files)} files in {duration:.2f}s "
                   f"(avg {duration/len(created_files):.2f}s per file)")
        
        # Test concurrent file access
        logger.info("Testing concurrent file access...")
        
        access_tasks = []
        for file_id, filename in created_files:
            # Find corresponding password
            password = next(f['password'] for f in test_files if f['filename'] == filename)
            task = file_manager.access_file_async(
                file_id=file_id,
                password=password,
                progress_callback=progress_callback
            )
            access_tasks.append(task)
        
        start_time = time.time()
        access_results = await asyncio.gather(*access_tasks)
        duration = time.time() - start_time
        
        logger.info(f"📊 Accessed {len(access_results)} files in {duration:.2f}s "
                   f"(avg {duration/len(access_results):.2f}s per file)")
        
        # Display performance metrics
        perf_metrics = file_manager.get_performance_metrics()
        logger.info(f"📈 File Manager Performance:")
        logger.info(f"   - Active operations: {perf_metrics['active_operations']}")
        logger.info(f"   - Memory usage: {perf_metrics['memory_usage']}")
        logger.info(f"   - Async file ops: {perf_metrics['async_file_operations']}")
        
        return created_files


async def demo_async_file_scanner():
    """Demonstrate concurrent file scanning."""
    logger = logging.getLogger("AsyncFileScanner")
    logger.info("🔍 Starting async file scanner demonstration...")
    
    async with AsyncFileScanner(max_workers=6, max_concurrent_scans=3) as scanner:
        
        # Discover available devices
        logger.info("Discovering storage devices...")
        devices = await scanner.discover_devices_async()
        
        logger.info(f"Found {len(devices)} storage devices:")
        for device in devices:
            logger.info(f"   - {device.name} ({device.path}) - {device.type}")
        
        if not devices:
            logger.warning("No devices found for scanning")
            return []
        
        # Select devices to scan (limit to first 3 for demo)
        scan_devices = devices[:3]
        
        # Progress tracking callback
        async def scan_progress_callback(progress_data):
            scan_id = progress_data.get('scan_id', 'unknown')
            processed = progress_data.get('processed_directories', 0)
            total = progress_data.get('total_directories', 0)
            found = progress_data.get('bar_files_found', 0)
            logger.debug(f"Scan {scan_id}: {processed}/{total} dirs, {found} .bar files found")
        
        # Start concurrent scans
        scan_ids = []
        for device in scan_devices:
            try:
                scan_id = await scanner.scan_device_async(
                    device.path, 
                    recursive=True,
                    progress_callback=scan_progress_callback
                )
                scan_ids.append(scan_id)
                logger.info(f"Started scan {scan_id} for {device.name}")
            except Exception as e:
                logger.error(f"Failed to start scan for {device.path}: {e}")
        
        # Monitor scan progress
        logger.info(f"Monitoring {len(scan_ids)} concurrent scans...")
        
        completed_scans = set()
        start_time = time.time()
        
        while len(completed_scans) < len(scan_ids):
            await asyncio.sleep(1)  # Check every second
            
            for scan_id in scan_ids:
                if scan_id in completed_scans:
                    continue
                
                progress = await scanner.get_scan_progress(scan_id)
                if progress and progress.status in ['completed', 'failed', 'cancelled']:
                    completed_scans.add(scan_id)
                    logger.info(f"✅ Scan {scan_id} {progress.status}: "
                               f"{progress.bar_files_found} .bar files found")
            
            # Timeout after 30 seconds for demo
            if time.time() - start_time > 30:
                logger.warning("Demo timeout reached, cancelling remaining scans")
                for scan_id in scan_ids:
                    if scan_id not in completed_scans:
                        await scanner.cancel_scan(scan_id)
                break
        
        # Get discovered .bar files
        discovered_files = await scanner.get_discovered_bar_files()
        
        logger.info(f"📊 Scan Summary:")
        logger.info(f"   - Total .bar files found: {len(discovered_files)}")
        
        for bar_file in discovered_files[:5]:  # Show first 5
            logger.info(f"   - {bar_file.file_path} ({bar_file.file_size:,} bytes) "
                       f"{'✓' if bar_file.is_valid else '✗'}")
        
        # Display scan statistics
        scan_stats = scanner.get_scan_statistics()
        logger.info(f"📈 Scanner Performance:")
        logger.info(f"   - Completed scans: {scan_stats['completed_scans']}")
        logger.info(f"   - Average scan speed: {scan_stats['average_scan_speed']:.1f} dirs/s")
        logger.info(f"   - Max concurrent scans: {scan_stats['max_concurrent_scans']}")
        
        return discovered_files


async def demo_performance_monitoring():
    """Demonstrate comprehensive performance monitoring."""
    logger = logging.getLogger("PerformanceMonitoring")
    logger.info("📊 Starting performance monitoring demonstration...")
    
    # Create performance monitor
    perf_monitor = PerformanceMonitor(
        monitoring_interval=2,  # Monitor every 2 seconds
        history_retention_hours=1  # Keep 1 hour of history
    )
    
    # Add alert callback
    async def alert_callback(alert_data):
        logger.warning(f"🚨 PERFORMANCE ALERT: {alert_data['metric_name']} = "
                      f"{alert_data['metric_value']:.2f} ({alert_data['alert_level']})")
    
    perf_monitor.add_alert_callback(alert_callback)
    
    # Start monitoring
    await perf_monitor.start_monitoring()
    
    try:
        # Simulate some workload to generate metrics
        logger.info("Generating workload for monitoring...")
        
        # Start operation tracking
        operation_id = "demo_operation_001"
        perf_monitor.start_operation_tracking(
            operation_id=operation_id,
            operation_type="demo_workload", 
            data_size_bytes=10 * 1024 * 1024,  # 10MB
            metadata={"demo": True}
        )
        
        # Simulate work with some CPU and memory usage
        await asyncio.sleep(5)  # Let monitoring collect baseline
        
        # CPU-intensive task
        def cpu_intensive_task():
            result = 0
            for i in range(1000000):
                result += i * i
            return result
        
        # Memory-intensive task  
        def memory_intensive_task():
            data = []
            for i in range(100):
                data.append(b'x' * (100 * 1024))  # 100KB chunks
            return len(data)
        
        # Run tasks in thread pool
        loop = asyncio.get_event_loop()
        from concurrent.futures import ThreadPoolExecutor
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Run multiple tasks concurrently
            tasks = [
                loop.run_in_executor(executor, cpu_intensive_task),
                loop.run_in_executor(executor, cpu_intensive_task),  
                loop.run_in_executor(executor, memory_intensive_task),
                loop.run_in_executor(executor, memory_intensive_task)
            ]
            
            results = await asyncio.gather(*tasks)
            logger.info(f"Workload completed: {results}")
        
        # Finish operation tracking
        perf_monitor.finish_operation_tracking(
            operation_id=operation_id,
            success=True,
            memory_peak_bytes=50 * 1024 * 1024  # 50MB peak
        )
        
        # Wait for metrics collection
        await asyncio.sleep(10)
        
        # Get comprehensive metrics
        metrics = perf_monitor.get_comprehensive_metrics()
        
        logger.info("📈 Performance Metrics Summary:")
        logger.info(f"System Health Score: {metrics['system_health']['score']}/100 "
                   f"({metrics['system_health']['status']})")
        
        if metrics['system_metrics']['current']:
            current = metrics['system_metrics']['current']
            logger.info(f"Current CPU: {current['cpu_percent']:.1f}%")
            logger.info(f"Current Memory: {current['memory_percent']:.1f}%")
            logger.info(f"Threads: {current['thread_count']}")
        
        op_stats = metrics['operation_statistics']['overall']
        if op_stats['operation_count'] > 0:
            logger.info(f"Operations: {op_stats['operation_count']} "
                       f"({op_stats['success_rate']*100:.1f}% success rate)")
            logger.info(f"Avg Duration: {op_stats['average_duration_seconds']:.2f}s")
            logger.info(f"Avg Throughput: {op_stats['average_throughput_bytes_per_second']/1024/1024:.2f} MB/s")
        
        # Test auto-optimization
        logger.info("Testing automatic performance optimization...")
        optimization_result = await perf_monitor.optimizer.analyze_and_optimize()
        logger.info(f"Optimization result: {optimization_result}")
        
        return metrics
        
    finally:
        await perf_monitor.stop_monitoring()


async def demo_integrated_performance():
    """Demonstrate all components working together with performance monitoring."""
    logger = logging.getLogger("IntegratedDemo")
    logger.info("🚀 Starting integrated performance demonstration...")
    
    # Set up performance monitor
    perf_monitor = PerformanceMonitor(monitoring_interval=3)
    await perf_monitor.start_monitoring()
    
    try:
        # Create demo directory
        demo_dir = Path.cwd() / "integrated_demo" 
        demo_dir.mkdir(exist_ok=True)
        
        # Initialize all async components
        async with AsyncEncryptionManager(max_workers=4) as enc_manager, \
                   AsyncFileManager(str(demo_dir), max_workers=6) as file_manager, \
                   AsyncFileScanner(max_workers=4) as scanner:
            
            # Connect components to performance monitor
            perf_monitor.async_encryption = enc_manager
            perf_monitor.async_file_manager = file_manager
            perf_monitor.async_file_scanner = scanner
            
            logger.info("All async components initialized")
            
            # Comprehensive workflow test
            logger.info("Starting comprehensive workflow...")
            
            # 1. Create multiple files concurrently
            file_tasks = []
            for i in range(5):
                content = f"Integrated demo file {i} content".encode() * 10000
                task = file_manager.create_secure_file_async(
                    content=content,
                    filename=f"demo_file_{i}.txt",
                    password=f"password_{i}",
                    security_settings={'max_access_count': 10}
                )
                file_tasks.append(task)
            
            created_files = await asyncio.gather(*file_tasks)
            logger.info(f"✅ Created {len(created_files)} files concurrently")
            
            # 2. Scan for files while accessing existing ones
            scan_task = asyncio.create_task(
                scanner.scan_device_async(str(demo_dir), recursive=True)
            )
            
            # 3. Access files concurrently while scan is running  
            access_tasks = []
            for i, (file_id, _) in enumerate(created_files):
                task = file_manager.access_file_async(file_id, f"password_{i}")
                access_tasks.append(task)
            
            access_results = await asyncio.gather(*access_tasks)
            logger.info(f"✅ Accessed {len(access_results)} files concurrently")
            
            # Wait for scan to complete
            scan_id = await scan_task
            logger.info(f"✅ File scan completed: {scan_id}")
            
            # 4. Get comprehensive performance metrics
            await asyncio.sleep(5)  # Let metrics settle
            
            final_metrics = perf_monitor.get_comprehensive_metrics()
            
            logger.info("🎯 Final Performance Summary:")
            logger.info(f"System Health: {final_metrics['system_health']['score']}/100")
            logger.info(f"Total Operations: {final_metrics['operation_statistics']['overall']['operation_count']}")
            logger.info(f"Success Rate: {final_metrics['operation_statistics']['overall']['success_rate']*100:.1f}%")
            
            # Export metrics for analysis
            metrics_file = demo_dir / "performance_metrics.json"
            perf_monitor.export_metrics(str(metrics_file))
            logger.info(f"📄 Performance metrics exported to {metrics_file}")
            
            return final_metrics
            
    finally:
        await perf_monitor.stop_monitoring()


async def main():
    """Main demonstration function."""
    logger = setup_logging()
    logger.info("🔥 BAR Async Performance Demonstration Starting...")
    logger.info("=" * 60)
    
    try:
        # Individual component demonstrations
        logger.info("Phase 1: Individual Component Demonstrations")
        
        # 1. Async Encryption Demo
        encryption_results = await demo_async_encryption()
        await asyncio.sleep(2)
        
        # 2. Async File Manager Demo
        file_manager_results = await demo_async_file_manager() 
        await asyncio.sleep(2)
        
        # 3. Async File Scanner Demo
        scanner_results = await demo_async_file_scanner()
        await asyncio.sleep(2)
        
        # 4. Performance Monitoring Demo
        monitoring_results = await demo_performance_monitoring()
        await asyncio.sleep(2)
        
        logger.info("=" * 60)
        logger.info("Phase 2: Integrated Performance Demonstration")
        
        # 5. Integrated Demo
        integrated_results = await demo_integrated_performance()
        
        logger.info("=" * 60)
        logger.info("🎉 All demonstrations completed successfully!")
        
        # Summary
        logger.info("📊 DEMONSTRATION SUMMARY:")
        logger.info(f"✅ Encryption operations: {len(encryption_results)} files processed")
        logger.info(f"✅ File management: {len(file_manager_results)} files created")
        logger.info(f"✅ File scanning: {len(scanner_results)} .bar files discovered")
        logger.info(f"✅ Performance monitoring: {monitoring_results['monitoring_status']['metrics_collected']} metrics collected")
        logger.info(f"✅ Integrated workflow: {integrated_results['system_health']['score']}/100 final health score")
        
    except Exception as e:
        logger.error(f"❌ Demonstration failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    # Set up event loop policy for Windows if needed
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    # Run the demonstration
    asyncio.run(main())