//! Minimal, exact-name `ControlTraceW` wrapper used only for project Session cleanup.

use std::mem::{align_of, size_of, size_of_val};
use std::ptr;

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_MORE_DATA, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND,
};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES, WNODE_FLAG_TRACED_GUID,
};
use windows::core::PCWSTR;

// Microsoft documents 1024 characters as the maximum when the Session and log file name lengths
// are not known to a ControlTrace caller.
const MAX_SESSION_NAME_CHARS: usize = 1024;
const MAX_LOG_FILE_NAME_CHARS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlOperation {
    Query,
    Stop,
}

impl ControlOperation {
    const fn native(self) -> EVENT_TRACE_CONTROL {
        match self {
            Self::Query => EVENT_TRACE_CONTROL_QUERY,
            Self::Stop => EVENT_TRACE_CONTROL_STOP,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlResult {
    Success,
    NotFound,
    AccessDenied,
    MoreData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeTraceStatistics {
    pub buffer_size_kb: u32,
    pub minimum_buffers: u32,
    pub maximum_buffers: u32,
    pub active_buffers: u32,
    pub free_buffers: u32,
    pub events_lost: u32,
    pub buffers_written: u32,
    pub log_buffers_lost: u32,
    pub real_time_buffers_lost: u32,
}

/// Calls `ControlTraceW` for one exact Session name.
pub(crate) fn control_session(
    session_name: &str,
    operation: ControlOperation,
) -> Result<ControlResult, u32> {
    let wide_name = encode_wide(session_name)?;
    let mut buffer = PropertiesBuffer::new(&wide_name)?;

    let status = unsafe {
        // SAFETY: `wide_name` is NUL-terminated and remains alive for the call. `buffer` owns an
        // aligned, zero-initialized contiguous allocation whose first bytes contain a valid
        // EVENT_TRACE_PROPERTIES and whose name offsets point inside that allocation.
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            PCWSTR::from_raw(wide_name.as_ptr()),
            buffer.properties_ptr(),
            operation.native(),
        )
    };

    if status == ERROR_SUCCESS {
        Ok(ControlResult::Success)
    } else if status == ERROR_WMI_INSTANCE_NOT_FOUND {
        Ok(ControlResult::NotFound)
    } else if status == ERROR_ACCESS_DENIED {
        Ok(ControlResult::AccessDenied)
    } else if status == ERROR_MORE_DATA {
        Ok(ControlResult::MoreData)
    } else {
        Err(status.0)
    }
}

/// Queries live statistics for one exact Session name.
pub(crate) fn query_session_statistics(
    session_name: &str,
) -> Result<Option<NativeTraceStatistics>, u32> {
    let wide_name = encode_wide(session_name)?;
    let mut buffer = PropertiesBuffer::new(&wide_name)?;
    // SAFETY: The exact same allocation and name invariants documented in `control_session` apply;
    // EVENT_TRACE_CONTROL_QUERY writes the returned statistics into the owned properties buffer.
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            PCWSTR::from_raw(wide_name.as_ptr()),
            buffer.properties_ptr(),
            EVENT_TRACE_CONTROL_QUERY,
        )
    };

    if status == ERROR_SUCCESS {
        Ok(Some(buffer.statistics()))
    } else if status == ERROR_WMI_INSTANCE_NOT_FOUND {
        Ok(None)
    } else {
        Err(status.0)
    }
}

fn encode_wide(value: &str) -> Result<Vec<u16>, u32> {
    let mut wide = value.encode_utf16().collect::<Vec<_>>();
    if wide.len() > MAX_SESSION_NAME_CHARS || wide.contains(&0) {
        return Err(87); // ERROR_INVALID_PARAMETER
    }
    wide.push(0);
    Ok(wide)
}

struct PropertiesBuffer {
    // usize provides at least the alignment required by EVENT_TRACE_PROPERTIES on Windows targets.
    storage: Vec<usize>,
}

impl PropertiesBuffer {
    fn new(session_name: &[u16]) -> Result<Self, u32> {
        let properties_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let logger_name_bytes = (MAX_SESSION_NAME_CHARS + 1)
            .checked_mul(size_of::<u16>())
            .ok_or(534u32)?; // ERROR_ARITHMETIC_OVERFLOW
        let log_file_name_bytes = (MAX_LOG_FILE_NAME_CHARS + 1)
            .checked_mul(size_of::<u16>())
            .ok_or(534u32)?;
        let log_file_offset = properties_size
            .checked_add(logger_name_bytes)
            .ok_or(534u32)?;
        let required_bytes = log_file_offset
            .checked_add(log_file_name_bytes)
            .ok_or(534u32)?;
        let word_size = size_of::<usize>();
        let word_count = required_bytes.div_ceil(word_size);
        let storage = vec![0usize; word_count];
        let actual_bytes = storage.len().checked_mul(word_size).ok_or(534u32)?;
        let buffer_size = u32::try_from(actual_bytes).map_err(|_| 534u32)?;
        let logger_name_offset = u32::try_from(properties_size).map_err(|_| 534u32)?;
        let log_file_name_offset = u32::try_from(log_file_offset).map_err(|_| 534u32)?;

        debug_assert!(align_of::<usize>() >= align_of::<EVENT_TRACE_PROPERTIES>());
        let mut result = Self { storage };
        let properties_ptr = result.properties_ptr();
        unsafe {
            // SAFETY: `storage` is aligned for EVENT_TRACE_PROPERTIES, contains at least
            // `size_of::<EVENT_TRACE_PROPERTIES>()` bytes, and is zero-initialized. Writing a
            // default value initializes the structure without exceeding the allocation.
            ptr::write(properties_ptr, EVENT_TRACE_PROPERTIES::default());
            (*properties_ptr).Wnode.BufferSize = buffer_size;
            (*properties_ptr).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*properties_ptr).LoggerNameOffset = logger_name_offset;
            (*properties_ptr).LogFileNameOffset = log_file_name_offset;

            // SAFETY: LoggerNameOffset points to a `(MAX_SESSION_NAME_CHARS + 1)` u16-sized region
            // in the same allocation. `encode_wide` bounds the source length and includes its NUL.
            // Copying as bytes avoids constructing a potentially misaligned u16 pointer.
            let destination = result
                .storage
                .as_mut_ptr()
                .cast::<u8>()
                .add(properties_size);
            let name_bytes = size_of_val(session_name);
            ptr::copy_nonoverlapping(session_name.as_ptr().cast::<u8>(), destination, name_bytes);
        }
        Ok(result)
    }

    fn properties_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.storage.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>()
    }

    fn statistics(&mut self) -> NativeTraceStatistics {
        // SAFETY: `PropertiesBuffer::new` initialized this allocation with a valid
        // EVENT_TRACE_PROPERTIES, and a successful query has populated its statistics fields.
        let properties = unsafe { &*self.properties_ptr() };
        NativeTraceStatistics {
            buffer_size_kb: properties.BufferSize,
            minimum_buffers: properties.MinimumBuffers,
            maximum_buffers: properties.MaximumBuffers,
            active_buffers: properties.NumberOfBuffers,
            free_buffers: properties.FreeBuffers,
            events_lost: properties.EventsLost,
            buffers_written: properties.BuffersWritten,
            log_buffers_lost: properties.LogBuffersLost,
            real_time_buffers_lost: properties.RealTimeBuffersLost,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_LOG_FILE_NAME_CHARS, MAX_SESSION_NAME_CHARS, PropertiesBuffer, encode_wide};
    use std::mem::size_of;
    use windows::Win32::System::Diagnostics::Etw::{
        EVENT_TRACE_PROPERTIES, WNODE_FLAG_TRACED_GUID,
    };

    #[test]
    fn properties_buffer_uses_computed_contiguous_offsets() {
        let name = encode_wide("ProcNetRecorder-V0-TcpIp-Probe").unwrap();
        let mut buffer = PropertiesBuffer::new(&name).unwrap();
        let properties = unsafe {
            // SAFETY: `buffer` constructs and owns a valid EVENT_TRACE_PROPERTIES at this pointer.
            &*buffer.properties_ptr()
        };
        let structure_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let expected_log_offset = structure_size + (MAX_SESSION_NAME_CHARS + 1) * size_of::<u16>();
        let minimum_size = expected_log_offset + (MAX_LOG_FILE_NAME_CHARS + 1) * size_of::<u16>();

        assert_eq!(properties.LoggerNameOffset as usize, structure_size);
        assert_eq!(properties.LogFileNameOffset as usize, expected_log_offset);
        assert!(properties.Wnode.BufferSize as usize >= minimum_size);
        assert_eq!(properties.Wnode.Flags, WNODE_FLAG_TRACED_GUID);
    }
}
