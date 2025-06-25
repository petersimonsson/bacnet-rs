//! Utility Functions Module
//!
//! This module provides common utility functions and helpers used throughout the
//! BACnet stack implementation. These utilities include data conversion, validation,
//! debugging tools, and other helper functions.
//!
//! # Overview
//!
//! Utilities provided include:
//! - CRC calculation for MS/TP
//! - Data conversion helpers
//! - Time and date utilities
//! - Debugging and logging helpers
//! - Buffer management utilities
//! - BACnet-specific validations
//!
//! # Example
//!
//! ```no_run
//! use bacnet_rs::util::*;
//!
//! // Example of using CRC calculation
//! let data = b"Hello BACnet";
//! let crc = crc16_mstp(data);
//! ```

// TODO: Will be needed for debug formatting
// #[cfg(feature = "std")]
// use std::fmt;
// #[cfg(not(feature = "std"))]
// use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{
    time::{Duration, Instant},
    sync::{Arc, Mutex},
    collections::HashMap,
};

#[cfg(not(feature = "std"))]  
use alloc::collections::BTreeMap as HashMap;

/// Calculate CRC-16 for MS/TP frames
///
/// Uses the polynomial x^16 + x^15 + x^2 + 1 (0xA001)
pub fn crc16_mstp(data: &[u8]) -> u16 {
    let mut crc = 0xFFFF;

    for byte in data {
        crc ^= *byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }

    !crc
}

/// Calculate CRC-32C (Castagnoli) for BACnet/SC
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFF;

    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
        }
    }

    !crc
}

/// Convert BACnet date to string representation
pub fn bacnet_date_to_string(year: u16, month: u8, day: u8, weekday: u8) -> String {
    let year_str = if year == 255 {
        String::from("*")
    } else {
        format!("{}", year)
    };
    let month_str = match month {
        13 => String::from("odd"),
        14 => String::from("even"),
        255 => String::from("*"),
        _ => format!("{}", month),
    };
    let day_str = if day == 32 {
        String::from("last")
    } else if day == 255 {
        String::from("*")
    } else {
        format!("{}", day)
    };
    let weekday_str = if weekday == 255 {
        String::from("*")
    } else {
        String::from(match weekday {
            1 => "Mon",
            2 => "Tue",
            3 => "Wed",
            4 => "Thu",
            5 => "Fri",
            6 => "Sat",
            7 => "Sun",
            _ => "?",
        })
    };

    format!("{}/{}/{} ({})", year_str, month_str, day_str, weekday_str)
}

/// Convert BACnet time to string representation
pub fn bacnet_time_to_string(hour: u8, minute: u8, second: u8, hundredths: u8) -> String {
    let hour_str = if hour == 255 {
        String::from("*")
    } else {
        format!("{:02}", hour)
    };
    let minute_str = if minute == 255 {
        String::from("*")
    } else {
        format!("{:02}", minute)
    };
    let second_str = if second == 255 {
        String::from("*")
    } else {
        format!("{:02}", second)
    };
    let hundredths_str = if hundredths == 255 {
        String::from("*")
    } else {
        format!("{:02}", hundredths)
    };

    format!(
        "{}:{}:{}.{}",
        hour_str, minute_str, second_str, hundredths_str
    )
}

/// Validate object instance number (must be 0-4194302)
pub fn is_valid_instance_number(instance: u32) -> bool {
    instance <= 0x3FFFFF
}

/// Convert object type and instance to object identifier (32-bit)
pub fn encode_object_id(object_type: u16, instance: u32) -> Option<u32> {
    if object_type > 0x3FF || instance > 0x3FFFFF {
        return None;
    }
    Some(((object_type as u32) << 22) | instance)
}

/// Decode object identifier to object type and instance
pub fn decode_object_id(object_id: u32) -> (u16, u32) {
    let object_type = (object_id >> 22) as u16;
    let instance = object_id & 0x3FFFFF;
    (object_type, instance)
}

/// Buffer utilities for reading/writing data
pub struct Buffer<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Buffer<'a> {
    /// Create a new buffer reader
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Check if buffer has at least n bytes remaining
    pub fn has_remaining(&self, n: usize) -> bool {
        self.remaining() >= n
    }

    /// Read a single byte
    pub fn read_u8(&mut self) -> Option<u8> {
        if self.has_remaining(1) {
            let value = self.data[self.position];
            self.position += 1;
            Some(value)
        } else {
            None
        }
    }

    /// Read a 16-bit value (big-endian)
    pub fn read_u16(&mut self) -> Option<u16> {
        if self.has_remaining(2) {
            let value =
                u16::from_be_bytes([self.data[self.position], self.data[self.position + 1]]);
            self.position += 2;
            Some(value)
        } else {
            None
        }
    }

    /// Read a 32-bit value (big-endian)
    pub fn read_u32(&mut self) -> Option<u32> {
        if self.has_remaining(4) {
            let value = u32::from_be_bytes([
                self.data[self.position],
                self.data[self.position + 1],
                self.data[self.position + 2],
                self.data[self.position + 3],
            ]);
            self.position += 4;
            Some(value)
        } else {
            None
        }
    }

    /// Read n bytes
    pub fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.has_remaining(n) {
            let bytes = &self.data[self.position..self.position + n];
            self.position += n;
            Some(bytes)
        } else {
            None
        }
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Skip n bytes
    pub fn skip(&mut self, n: usize) -> bool {
        if self.has_remaining(n) {
            self.position += n;
            true
        } else {
            false
        }
    }
}

/// Hex dump utility for debugging
pub fn hex_dump(data: &[u8], prefix: &str) -> String {
    let mut result = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        result.push_str(prefix);
        result.push_str(&format!("{:04X}: ", i * 16));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                result.push(' ');
            }
            result.push_str(&format!("{:02X} ", byte));
        }

        // Padding
        for j in chunk.len()..16 {
            if j == 8 {
                result.push(' ');
            }
            result.push_str("   ");
        }

        result.push_str(" |");

        // ASCII representation
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                result.push(*byte as char);
            } else {
                result.push('.');
            }
        }

        result.push_str("|\n");
    }

    result
}

/// Priority array utilities
pub mod priority {
    /// BACnet priority levels (1-16, where 1 is highest)
    pub const MANUAL_LIFE_SAFETY: u8 = 1;
    pub const AUTOMATIC_LIFE_SAFETY: u8 = 2;
    pub const AVAILABLE_3: u8 = 3;
    pub const AVAILABLE_4: u8 = 4;
    pub const CRITICAL_EQUIPMENT_CONTROL: u8 = 5;
    pub const MINIMUM_ON_OFF: u8 = 6;
    pub const AVAILABLE_7: u8 = 7;
    pub const MANUAL_OPERATOR: u8 = 8;
    pub const AVAILABLE_9: u8 = 9;
    pub const AVAILABLE_10: u8 = 10;
    pub const AVAILABLE_11: u8 = 11;
    pub const AVAILABLE_12: u8 = 12;
    pub const AVAILABLE_13: u8 = 13;
    pub const AVAILABLE_14: u8 = 14;
    pub const AVAILABLE_15: u8 = 15;
    pub const LOWEST: u8 = 16;

    /// Check if priority is valid (1-16)
    pub fn is_valid(priority: u8) -> bool {
        priority >= 1 && priority <= 16
    }
}

/// Performance monitoring utilities
#[cfg(feature = "std")]
pub mod performance {
    use super::*;
    
    /// Performance metrics for a BACnet operation
    #[derive(Debug, Clone)]
    pub struct OperationMetrics {
        pub name: String,
        pub count: u64,
        pub total_duration_ms: f64,
        pub min_duration_ms: f64,
        pub max_duration_ms: f64,
        pub avg_duration_ms: f64,
        pub last_duration_ms: f64,
    }
    
    /// Performance monitor for tracking operation timing
    pub struct PerformanceMonitor {
        metrics: Arc<Mutex<HashMap<String, OperationMetrics>>>,
        active_timers: Arc<Mutex<HashMap<String, Instant>>>,
    }
    
    impl PerformanceMonitor {
        /// Create a new performance monitor
        pub fn new() -> Self {
            Self {
                metrics: Arc::new(Mutex::new(HashMap::new())),
                active_timers: Arc::new(Mutex::new(HashMap::new())),
            }
        }
        
        /// Start timing an operation
        pub fn start_timer(&self, operation: &str) {
            let mut timers = self.active_timers.lock().unwrap();
            timers.insert(operation.to_string(), Instant::now());
        }
        
        /// Stop timing an operation and record metrics
        pub fn stop_timer(&self, operation: &str) {
            let mut timers = self.active_timers.lock().unwrap();
            if let Some(start_time) = timers.remove(operation) {
                let duration = start_time.elapsed();
                let duration_ms = duration.as_secs_f64() * 1000.0;
                
                let mut metrics = self.metrics.lock().unwrap();
                let metric = metrics.entry(operation.to_string()).or_insert(OperationMetrics {
                    name: operation.to_string(),
                    count: 0,
                    total_duration_ms: 0.0,
                    min_duration_ms: f64::MAX,
                    max_duration_ms: 0.0,
                    avg_duration_ms: 0.0,
                    last_duration_ms: 0.0,
                });
                
                metric.count += 1;
                metric.total_duration_ms += duration_ms;
                metric.min_duration_ms = metric.min_duration_ms.min(duration_ms);
                metric.max_duration_ms = metric.max_duration_ms.max(duration_ms);
                metric.avg_duration_ms = metric.total_duration_ms / metric.count as f64;
                metric.last_duration_ms = duration_ms;
            }
        }
        
        /// Get metrics for a specific operation
        pub fn get_metrics(&self, operation: &str) -> Option<OperationMetrics> {
            let metrics = self.metrics.lock().unwrap();
            metrics.get(operation).cloned()
        }
        
        /// Get all metrics
        pub fn get_all_metrics(&self) -> Vec<OperationMetrics> {
            let metrics = self.metrics.lock().unwrap();
            metrics.values().cloned().collect()
        }
        
        /// Clear all metrics
        pub fn clear(&self) {
            self.metrics.lock().unwrap().clear();
            self.active_timers.lock().unwrap().clear();
        }
    }
    
    /// RAII timer for automatic performance tracking
    pub struct ScopedTimer<'a> {
        monitor: &'a PerformanceMonitor,
        operation: String,
    }
    
    impl<'a> ScopedTimer<'a> {
        /// Create a new scoped timer
        pub fn new(monitor: &'a PerformanceMonitor, operation: &str) -> Self {
            monitor.start_timer(operation);
            Self {
                monitor,
                operation: operation.to_string(),
            }
        }
    }
    
    impl<'a> Drop for ScopedTimer<'a> {
        fn drop(&mut self) {
            self.monitor.stop_timer(&self.operation);
        }
    }
}

/// Statistics collection helpers
pub mod statistics {
    use super::*;
    
    /// BACnet communication statistics
    #[derive(Debug, Default, Clone)]
    pub struct CommunicationStats {
        pub messages_sent: u64,
        pub messages_received: u64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub errors: u64,
        pub timeouts: u64,
        pub retries: u64,
        pub acks_received: u64,
        pub naks_received: u64,
        pub rejects_received: u64,
        pub aborts_received: u64,
    }
    
    impl CommunicationStats {
        /// Create new statistics
        pub fn new() -> Self {
            Self::default()
        }
        
        /// Record a sent message
        pub fn record_sent(&mut self, bytes: usize) {
            self.messages_sent += 1;
            self.bytes_sent += bytes as u64;
        }
        
        /// Record a received message
        pub fn record_received(&mut self, bytes: usize) {
            self.messages_received += 1;
            self.bytes_received += bytes as u64;
        }
        
        /// Record an error
        pub fn record_error(&mut self) {
            self.errors += 1;
        }
        
        /// Record a timeout
        pub fn record_timeout(&mut self) {
            self.timeouts += 1;
        }
        
        /// Record a retry
        pub fn record_retry(&mut self) {
            self.retries += 1;
        }
        
        /// Get success rate percentage
        pub fn success_rate(&self) -> f64 {
            let total = self.messages_sent as f64;
            if total == 0.0 {
                return 100.0;
            }
            let failures = (self.errors + self.timeouts) as f64;
            ((total - failures) / total) * 100.0
        }
        
        /// Reset all statistics
        pub fn reset(&mut self) {
            *self = Self::default();
        }
    }
    
    /// Device-specific statistics
    #[derive(Debug, Clone)]
    pub struct DeviceStats {
        pub device_id: u32,
        pub address: String,
        pub comm_stats: CommunicationStats,
        pub last_seen: Option<Instant>,
        pub response_times_ms: Vec<f64>,
        pub online: bool,
    }
    
    #[cfg(feature = "std")]
    impl DeviceStats {
        /// Create new device statistics
        pub fn new(device_id: u32, address: String) -> Self {
            Self {
                device_id,
                address,
                comm_stats: CommunicationStats::new(),
                last_seen: None,
                response_times_ms: Vec::new(),
                online: false,
            }
        }
        
        /// Record a response time
        pub fn record_response_time(&mut self, ms: f64) {
            self.response_times_ms.push(ms);
            // Keep only last 100 response times
            if self.response_times_ms.len() > 100 {
                self.response_times_ms.remove(0);
            }
            self.last_seen = Some(Instant::now());
            self.online = true;
        }
        
        /// Get average response time
        pub fn avg_response_time(&self) -> Option<f64> {
            if self.response_times_ms.is_empty() {
                return None;
            }
            let sum: f64 = self.response_times_ms.iter().sum();
            Some(sum / self.response_times_ms.len() as f64)
        }
        
        /// Mark device as offline
        pub fn mark_offline(&mut self) {
            self.online = false;
        }
    }
    
    /// Statistics collector for multiple devices
    #[cfg(feature = "std")]
    pub struct StatsCollector {
        devices: Arc<Mutex<HashMap<u32, DeviceStats>>>,
        global_stats: Arc<Mutex<CommunicationStats>>,
    }
    
    #[cfg(feature = "std")]
    impl StatsCollector {
        /// Create a new statistics collector
        pub fn new() -> Self {
            Self {
                devices: Arc::new(Mutex::new(HashMap::new())),
                global_stats: Arc::new(Mutex::new(CommunicationStats::new())),
            }
        }
        
        /// Get or create device statistics
        pub fn get_device_stats(&self, device_id: u32, address: String) -> DeviceStats {
            let mut devices = self.devices.lock().unwrap();
            devices.entry(device_id)
                .or_insert_with(|| DeviceStats::new(device_id, address))
                .clone()
        }
        
        /// Update device statistics
        pub fn update_device_stats<F>(&self, device_id: u32, updater: F)
        where
            F: FnOnce(&mut DeviceStats),
        {
            let mut devices = self.devices.lock().unwrap();
            if let Some(stats) = devices.get_mut(&device_id) {
                updater(stats);
            }
        }
        
        /// Get global statistics
        pub fn get_global_stats(&self) -> CommunicationStats {
            self.global_stats.lock().unwrap().clone()
        }
        
        /// Update global statistics
        pub fn update_global_stats<F>(&self, updater: F)
        where
            F: FnOnce(&mut CommunicationStats),
        {
            let mut stats = self.global_stats.lock().unwrap();
            updater(&mut stats);
        }
        
        /// Get all device statistics
        pub fn get_all_device_stats(&self) -> Vec<DeviceStats> {
            let devices = self.devices.lock().unwrap();
            devices.values().cloned().collect()
        }
        
        /// Clear all statistics
        pub fn clear(&self) {
            self.devices.lock().unwrap().clear();
            self.global_stats.lock().unwrap().reset();
        }
    }
}

/// Additional utility functions

/// Validate BACnet network number (0-65534, 65535 is broadcast)
pub fn is_valid_network_number(network: u16) -> bool {
    // All u16 values are valid network numbers
    true
}

/// Check if network number is local (0)
pub fn is_local_network(network: u16) -> bool {
    network == 0
}

/// Check if network number is broadcast (65535)
pub fn is_broadcast_network(network: u16) -> bool {
    network == 65535
}

/// Parse BACnet address from string (e.g., "192.168.1.100:47808")
#[cfg(feature = "std")]
pub fn parse_bacnet_address(address: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    
    // If no port specified, add default BACnet port
    let addr_with_port = if address.contains(':') {
        address.to_string()
    } else {
        format!("{}:47808", address)
    };
    
    addr_with_port
        .to_socket_addrs()
        .map_err(|e| format!("Invalid address: {}", e))?
        .next()
        .ok_or_else(|| "No valid address found".to_string())
}

/// Format bytes as human-readable size
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// Calculate message throughput
pub fn calculate_throughput(bytes: u64, duration_secs: f64) -> String {
    if duration_secs == 0.0 {
        return "N/A".to_string();
    }
    
    let bytes_per_sec = bytes as f64 / duration_secs;
    format!("{}/s", format_bytes(bytes_per_sec as u64))
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Calculate delay for a given attempt (0-based)
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay_ms = if attempt == 0 {
            self.initial_delay_ms
        } else {
            let delay = self.initial_delay_ms as f64 * self.backoff_multiplier.powi(attempt as i32);
            delay.min(self.max_delay_ms as f64) as u64
        };
        
        Duration::from_millis(delay_ms)
    }
}

/// Circular buffer for maintaining history
#[derive(Debug, Clone)]
pub struct CircularBuffer<T> {
    buffer: Vec<Option<T>>,
    capacity: usize,
    head: usize,
    size: usize,
}

impl<T: Clone> CircularBuffer<T> {
    /// Create a new circular buffer with given capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![None; capacity],
            capacity,
            head: 0,
            size: 0,
        }
    }
    
    /// Add an item to the buffer
    pub fn push(&mut self, item: T) {
        self.buffer[self.head] = Some(item);
        self.head = (self.head + 1) % self.capacity;
        if self.size < self.capacity {
            self.size += 1;
        }
    }
    
    /// Get all items in order (oldest to newest)
    pub fn items(&self) -> Vec<T> {
        let mut result = Vec::with_capacity(self.size);
        
        if self.size < self.capacity {
            // Buffer not full, items are from 0 to head
            for i in 0..self.size {
                if let Some(item) = &self.buffer[i] {
                    result.push(item.clone());
                }
            }
        } else {
            // Buffer full, items wrap around
            for i in 0..self.capacity {
                let idx = (self.head + i) % self.capacity;
                if let Some(item) = &self.buffer[idx] {
                    result.push(item.clone());
                }
            }
        }
        
        result
    }
    
    /// Get the number of items in the buffer
    pub fn len(&self) -> usize {
        self.size
    }
    
    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
    
    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer = vec![None; self.capacity];
        self.head = 0;
        self.size = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }
    
    #[test]
    fn test_circular_buffer() {
        let mut buffer = CircularBuffer::new(3);
        
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        
        buffer.push(1);
        buffer.push(2);
        buffer.push(3);
        
        assert_eq!(buffer.items(), vec![1, 2, 3]);
        assert_eq!(buffer.len(), 3);
        
        // Test wraparound
        buffer.push(4);
        assert_eq!(buffer.items(), vec![2, 3, 4]);
        
        buffer.push(5);
        assert_eq!(buffer.items(), vec![3, 4, 5]);
    }
    
    #[test]
    fn test_retry_config() {
        let config = RetryConfig::default();
        
        assert_eq!(config.delay_for_attempt(0).as_millis(), 100);
        assert_eq!(config.delay_for_attempt(1).as_millis(), 200);
        assert_eq!(config.delay_for_attempt(2).as_millis(), 400);
        assert_eq!(config.delay_for_attempt(3).as_millis(), 800);
        
        // Test max delay
        assert_eq!(config.delay_for_attempt(10).as_millis(), 5000);
    }
    
    #[cfg(feature = "std")]
    #[test]
    fn test_parse_bacnet_address() {
        assert!(parse_bacnet_address("192.168.1.100:47808").is_ok());
        assert!(parse_bacnet_address("192.168.1.100").is_ok());
        assert!(parse_bacnet_address("invalid").is_err());
    }
    
    #[cfg(feature = "std")]
    #[test]
    fn test_communication_stats() {
        let mut stats = statistics::CommunicationStats::new();
        
        stats.record_sent(100);
        stats.record_received(150);
        
        assert_eq!(stats.messages_sent, 1);
        assert_eq!(stats.messages_received, 1);
        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.bytes_received, 150);
        assert_eq!(stats.success_rate(), 100.0);
        
        stats.record_error();
        stats.record_timeout();
        
        assert!(stats.success_rate() < 100.0);
    }
    
    #[cfg(feature = "std")]
    #[test]
    fn test_performance_monitor() {
        use std::thread;
        use std::time::Duration;
        
        let monitor = performance::PerformanceMonitor::new();
        
        {
            let _timer = performance::ScopedTimer::new(&monitor, "test_operation");
            thread::sleep(Duration::from_millis(10));
        }
        
        let metrics = monitor.get_metrics("test_operation").unwrap();
        assert_eq!(metrics.count, 1);
        assert!(metrics.last_duration_ms >= 10.0);
        assert_eq!(metrics.min_duration_ms, metrics.max_duration_ms);
    }
}
