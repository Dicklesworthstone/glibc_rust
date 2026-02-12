//! ELF64 file header parsing.
//!
//! The ELF header is the first structure in any ELF file and contains
//! essential metadata for parsing the rest of the file.

use super::{EI_NIDENT, ELF_MAGIC, ElfError, ElfResult};

/// Indices into the e_ident array.
mod ident {
    pub const EI_CLASS: usize = 4;
    pub const EI_DATA: usize = 5;
    #[allow(dead_code)]
    pub const EI_VERSION: usize = 6;
    pub const EI_OSABI: usize = 7;
    pub const EI_ABIVERSION: usize = 8;
}

/// ELF class (32-bit or 64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ElfClass {
    /// Invalid class
    None = 0,
    /// 32-bit objects
    Elf32 = 1,
    /// 64-bit objects
    Elf64 = 2,
}

impl TryFrom<u8> for ElfClass {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Elf32),
            2 => Ok(Self::Elf64),
            _ => Err(value),
        }
    }
}

/// ELF data encoding (endianness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ElfData {
    /// Invalid encoding
    None = 0,
    /// Little-endian (2's complement)
    Lsb = 1,
    /// Big-endian (2's complement)
    Msb = 2,
}

impl TryFrom<u8> for ElfData {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Lsb),
            2 => Ok(Self::Msb),
            _ => Err(value),
        }
    }
}

/// ELF OS/ABI identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfOsAbi {
    /// UNIX System V ABI
    SysV,
    /// HP-UX
    HpUx,
    /// NetBSD
    NetBsd,
    /// GNU/Linux
    Gnu,
    /// Sun Solaris
    Solaris,
    /// IBM AIX
    Aix,
    /// SGI Irix
    Irix,
    /// FreeBSD
    FreeBsd,
    /// Standalone (embedded)
    Standalone,
    /// Unknown ABI
    Unknown(u8),
}

impl From<u8> for ElfOsAbi {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::SysV,
            1 => Self::HpUx,
            2 => Self::NetBsd,
            3 => Self::Gnu,
            6 => Self::Solaris,
            7 => Self::Aix,
            8 => Self::Irix,
            9 => Self::FreeBsd,
            255 => Self::Standalone,
            other => Self::Unknown(other),
        }
    }
}

/// ELF object file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    /// No file type
    None,
    /// Relocatable file
    Rel,
    /// Executable file
    Exec,
    /// Shared object file
    Dyn,
    /// Core file
    Core,
    /// Unknown type
    Unknown(u16),
}

impl From<u16> for ElfType {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Rel,
            2 => Self::Exec,
            3 => Self::Dyn,
            4 => Self::Core,
            other => Self::Unknown(other),
        }
    }
}

/// ELF machine architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfMachine {
    /// No machine
    None,
    /// Intel 80386
    I386,
    /// ARM
    Arm,
    /// AMD x86-64
    X86_64,
    /// ARM AARCH64
    Aarch64,
    /// RISC-V
    RiscV,
    /// Unknown machine
    Unknown(u16),
}

impl From<u16> for ElfMachine {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::None,
            3 => Self::I386,
            40 => Self::Arm,
            62 => Self::X86_64,
            183 => Self::Aarch64,
            243 => Self::RiscV,
            other => Self::Unknown(other),
        }
    }
}

impl ElfMachine {
    /// Convert to the raw u16 value.
    pub fn to_u16(self) -> u16 {
        match self {
            Self::None => 0,
            Self::I386 => 3,
            Self::Arm => 40,
            Self::X86_64 => 62,
            Self::Aarch64 => 183,
            Self::RiscV => 243,
            Self::Unknown(v) => v,
        }
    }
}

/// ELF64 file header.
///
/// This structure appears at offset 0 of every ELF64 file and describes
/// the file's organization.
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    /// ELF identification bytes
    pub e_ident: [u8; EI_NIDENT],
    /// Object file type
    pub e_type: ElfType,
    /// Machine architecture
    pub e_machine: ElfMachine,
    /// Object file version
    pub e_version: u32,
    /// Entry point virtual address
    pub e_entry: u64,
    /// Program header table file offset
    pub e_phoff: u64,
    /// Section header table file offset
    pub e_shoff: u64,
    /// Processor-specific flags
    pub e_flags: u32,
    /// ELF header size in bytes
    pub e_ehsize: u16,
    /// Program header table entry size
    pub e_phentsize: u16,
    /// Program header table entry count
    pub e_phnum: u16,
    /// Section header table entry size
    pub e_shentsize: u16,
    /// Section header table entry count
    pub e_shnum: u16,
    /// Section header string table index
    pub e_shstrndx: u16,
}

impl Elf64Header {
    /// Size of an ELF64 header in bytes.
    pub const SIZE: usize = 64;

    /// Parse an ELF64 header from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The buffer is too small
    /// - The magic bytes are invalid
    /// - The ELF class is not ELF64
    /// - The data encoding is not little-endian
    pub fn parse(data: &[u8]) -> ElfResult<Self> {
        if data.len() < Self::SIZE {
            return Err(ElfError::BufferTooSmall {
                needed: Self::SIZE,
                available: data.len(),
            });
        }

        // Validate magic
        if data[0..4] != ELF_MAGIC {
            return Err(ElfError::InvalidMagic);
        }

        // Validate class (must be ELF64)
        let class = data[ident::EI_CLASS];
        if class != ElfClass::Elf64 as u8 {
            return Err(ElfError::UnsupportedClass(class));
        }

        // Validate data encoding (must be little-endian for x86_64)
        let encoding = data[ident::EI_DATA];
        if encoding != ElfData::Lsb as u8 {
            return Err(ElfError::UnsupportedEncoding(encoding));
        }

        // Copy identification bytes
        let mut e_ident = [0u8; EI_NIDENT];
        e_ident.copy_from_slice(&data[0..EI_NIDENT]);

        // Parse fields (little-endian)
        let e_type = ElfType::from(u16::from_le_bytes([data[16], data[17]]));
        let e_machine = ElfMachine::from(u16::from_le_bytes([data[18], data[19]]));
        let e_version = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let e_entry = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
        let e_phoff = u64::from_le_bytes([
            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
        ]);
        let e_shoff = u64::from_le_bytes([
            data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
        ]);
        let e_flags = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
        let e_ehsize = u16::from_le_bytes([data[52], data[53]]);
        let e_phentsize = u16::from_le_bytes([data[54], data[55]]);
        let e_phnum = u16::from_le_bytes([data[56], data[57]]);
        let e_shentsize = u16::from_le_bytes([data[58], data[59]]);
        let e_shnum = u16::from_le_bytes([data[60], data[61]]);
        let e_shstrndx = u16::from_le_bytes([data[62], data[63]]);

        Ok(Self {
            e_ident,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        })
    }

    /// Get the ELF class from the identification bytes.
    pub fn class(&self) -> ElfClass {
        ElfClass::try_from(self.e_ident[ident::EI_CLASS]).unwrap_or(ElfClass::None)
    }

    /// Get the data encoding from the identification bytes.
    pub fn data(&self) -> ElfData {
        ElfData::try_from(self.e_ident[ident::EI_DATA]).unwrap_or(ElfData::None)
    }

    /// Get the OS/ABI from the identification bytes.
    pub fn osabi(&self) -> ElfOsAbi {
        ElfOsAbi::from(self.e_ident[ident::EI_OSABI])
    }

    /// Get the ABI version from the identification bytes.
    pub fn abi_version(&self) -> u8 {
        self.e_ident[ident::EI_ABIVERSION]
    }

    /// Check if this is a shared object (library).
    pub fn is_shared_object(&self) -> bool {
        matches!(self.e_type, ElfType::Dyn)
    }

    /// Check if this is an executable.
    pub fn is_executable(&self) -> bool {
        matches!(self.e_type, ElfType::Exec)
    }

    /// Check if this is for x86_64.
    pub fn is_x86_64(&self) -> bool {
        matches!(self.e_machine, ElfMachine::X86_64)
    }

    /// Validate that this header is suitable for loading on x86_64 Linux.
    pub fn validate_for_x86_64(&self) -> ElfResult<()> {
        if !self.is_x86_64() {
            return Err(ElfError::UnsupportedMachine(self.e_machine.to_u16()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_header() -> [u8; 64] {
        let mut header = [0u8; 64];
        // Magic
        header[0..4].copy_from_slice(&ELF_MAGIC);
        // Class = ELF64
        header[4] = 2;
        // Data = LSB
        header[5] = 1;
        // Version
        header[6] = 1;
        // OS/ABI = SysV
        header[7] = 0;
        // Type = DYN (shared object) - little endian
        header[16] = 3;
        header[17] = 0;
        // Machine = x86_64 (0x3e = 62)
        header[18] = 0x3e;
        header[19] = 0;
        // Version
        header[20] = 1;
        header[21] = 0;
        header[22] = 0;
        header[23] = 0;
        // e_ehsize = 64
        header[52] = 64;
        header[53] = 0;
        header
    }

    #[test]
    fn test_parse_valid_header() {
        let data = make_valid_header();
        let header = Elf64Header::parse(&data).unwrap();

        assert_eq!(header.class(), ElfClass::Elf64);
        assert_eq!(header.data(), ElfData::Lsb);
        assert!(header.is_shared_object());
        assert!(header.is_x86_64());
        assert_eq!(header.e_ehsize, 64);
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = make_valid_header();
        data[0] = 0x00;
        assert!(matches!(
            Elf64Header::parse(&data),
            Err(ElfError::InvalidMagic)
        ));
    }

    #[test]
    fn test_wrong_class() {
        let mut data = make_valid_header();
        data[4] = 1; // ELF32
        assert!(matches!(
            Elf64Header::parse(&data),
            Err(ElfError::UnsupportedClass(1))
        ));
    }

    #[test]
    fn test_wrong_endian() {
        let mut data = make_valid_header();
        data[5] = 2; // Big-endian
        assert!(matches!(
            Elf64Header::parse(&data),
            Err(ElfError::UnsupportedEncoding(2))
        ));
    }

    #[test]
    fn test_buffer_too_small() {
        let data = [0u8; 32];
        assert!(matches!(
            Elf64Header::parse(&data),
            Err(ElfError::BufferTooSmall {
                needed: 64,
                available: 32
            })
        ));
    }

    #[test]
    fn test_elf_type_conversion() {
        assert_eq!(ElfType::from(0u16), ElfType::None);
        assert_eq!(ElfType::from(1u16), ElfType::Rel);
        assert_eq!(ElfType::from(2u16), ElfType::Exec);
        assert_eq!(ElfType::from(3u16), ElfType::Dyn);
        assert_eq!(ElfType::from(4u16), ElfType::Core);
        assert!(matches!(ElfType::from(99u16), ElfType::Unknown(99)));
    }

    #[test]
    fn test_elf_machine_conversion() {
        assert_eq!(ElfMachine::from(0u16), ElfMachine::None);
        assert_eq!(ElfMachine::from(3u16), ElfMachine::I386);
        assert_eq!(ElfMachine::from(62u16), ElfMachine::X86_64);
        assert_eq!(ElfMachine::from(183u16), ElfMachine::Aarch64);
        assert!(matches!(ElfMachine::from(999u16), ElfMachine::Unknown(999)));
    }
}
