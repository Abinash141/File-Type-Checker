package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MagicSignature holds the expected bytes and offset for a file type
type MagicSignature struct {
	Offset      int
	Bytes       []byte
	Description string
}

// extensionMagicMap maps file extensions to their known magic number signatures
var extensionMagicMap = map[string][]MagicSignature{
	// Images
	".jpg":  {{0, []byte{0xFF, 0xD8, 0xFF}, "JPEG Image"}},
	".jpeg": {{0, []byte{0xFF, 0xD8, 0xFF}, "JPEG Image"}},
	".png":  {{0, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "PNG Image"}},
	".gif": {
		{0, []byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, "GIF87a"},
		{0, []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, "GIF89a"},
	},
	".bmp":  {{0, []byte{0x42, 0x4D}, "BMP Image"}},
	".webp": {{8, []byte{0x57, 0x45, 0x42, 0x50}, "WebP Image"}},
	".ico":  {{0, []byte{0x00, 0x00, 0x01, 0x00}, "ICO Image"}},
	".tiff": {
		{0, []byte{0x49, 0x49, 0x2A, 0x00}, "TIFF (little-endian)"},
		{0, []byte{0x4D, 0x4D, 0x00, 0x2A}, "TIFF (big-endian)"},
	},

	// Documents
	".pdf": {{0, []byte{0x25, 0x50, 0x44, 0x46}, "PDF Document"}},
	".doc": {{0, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "MS Word DOC"}},
	".xls": {{0, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "MS Excel XLS"}},
	".ppt": {{0, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "MS PowerPoint PPT"}},
	".docx": {{0, []byte{0x50, 0x4B, 0x03, 0x04}, "MS Word DOCX (ZIP-based)"}},
	".xlsx": {{0, []byte{0x50, 0x4B, 0x03, 0x04}, "MS Excel XLSX (ZIP-based)"}},
	".pptx": {{0, []byte{0x50, 0x4B, 0x03, 0x04}, "MS PowerPoint PPTX (ZIP-based)"}},

	// Archives
	".zip":  {{0, []byte{0x50, 0x4B, 0x03, 0x04}, "ZIP Archive"}},
	".gz":   {{0, []byte{0x1F, 0x8B}, "GZIP Archive"}},
	".tar":  {{257, []byte{0x75, 0x73, 0x74, 0x61, 0x72}, "TAR Archive"}},
	".bz2":  {{0, []byte{0x42, 0x5A, 0x68}, "BZ2 Archive"}},
	".7z":   {{0, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7-Zip Archive"}},
	".rar":  {{0, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, "RAR Archive"}},
	".zst":  {{0, []byte{0x28, 0xB5, 0x2F, 0xFD}, "Zstandard Archive"}},
	".xz":   {{0, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "XZ Archive"}},

	// Audio
	".mp3": {
		{0, []byte{0xFF, 0xFB}, "MP3 Audio"},
		{0, []byte{0xFF, 0xF3}, "MP3 Audio"},
		{0, []byte{0xFF, 0xF2}, "MP3 Audio"},
		{0, []byte{0x49, 0x44, 0x33}, "MP3 Audio (ID3 tag)"},
	},
	".wav":  {{0, []byte{0x52, 0x49, 0x46, 0x46}, "WAV Audio"}},
	".flac": {{0, []byte{0x66, 0x4C, 0x61, 0x43}, "FLAC Audio"}},
	".ogg":  {{0, []byte{0x4F, 0x67, 0x67, 0x53}, "OGG Audio"}},
	".m4a":  {{4, []byte{0x66, 0x74, 0x79, 0x70}, "M4A Audio"}},
	".aiff": {{0, []byte{0x46, 0x4F, 0x52, 0x4D}, "AIFF Audio"}},

	// Video
	".mp4": {
		{4, []byte{0x66, 0x74, 0x79, 0x70}, "MP4 Video"},
	},
	".mov": {{4, []byte{0x66, 0x74, 0x79, 0x70}, "QuickTime MOV"}},
	".avi": {{0, []byte{0x52, 0x49, 0x46, 0x46}, "AVI Video"}},
	".mkv": {{0, []byte{0x1A, 0x45, 0xDF, 0xA3}, "MKV Video"}},
	".wmv": {{0, []byte{0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11}, "WMV Video"}},
	".flv": {{0, []byte{0x46, 0x4C, 0x56, 0x01}, "FLV Video"}},
	".webm": {{0, []byte{0x1A, 0x45, 0xDF, 0xA3}, "WebM Video"}},
	".mpeg": {{0, []byte{0x00, 0x00, 0x01, 0xBA}, "MPEG Video"}},

	// Executables & Binaries
	".exe": {{0, []byte{0x4D, 0x5A}, "Windows Executable (PE)"}},
	".elf": {{0, []byte{0x7F, 0x45, 0x4C, 0x46}, "ELF Binary (Linux/Unix)"}},
	".dll": {{0, []byte{0x4D, 0x5A}, "Windows DLL"}},
	".so":  {{0, []byte{0x7F, 0x45, 0x4C, 0x46}, "Shared Object (Linux)"}},

	// Fonts
	".ttf":  {{0, []byte{0x00, 0x01, 0x00, 0x00}, "TrueType Font"}},
	".otf":  {{0, []byte{0x4F, 0x54, 0x54, 0x4F}, "OpenType Font"}},
	".woff": {{0, []byte{0x77, 0x4F, 0x46, 0x46}, "WOFF Font"}},
	".woff2": {{0, []byte{0x77, 0x4F, 0x46, 0x32}, "WOFF2 Font"}},

	// Other
	".sqlite": {{0, []byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, "SQLite Database"}},
	".db":     {{0, []byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, "SQLite Database"}},
	".class":  {{0, []byte{0xCA, 0xFE, 0xBA, 0xBE}, "Java Class File"}},
	".pyc":    {{0, []byte{0x0D, 0x0D, 0x0A, 0x0A}, "Python Compiled"}},
	".wasm":   {{0, []byte{0x00, 0x61, 0x73, 0x6D}, "WebAssembly Binary"}},
	".psd":    {{0, []byte{0x38, 0x42, 0x50, 0x53}, "Photoshop PSD"}},
	".swf":    {{0, []byte{0x43, 0x57, 0x53}, "Adobe Flash SWF"}},
	".rtf":    {{0, []byte{0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31}, "Rich Text Format"}},
	".iso":    {{32769, []byte{0x43, 0x44, 0x30, 0x30, 0x31}, "ISO Disc Image"}},
	".lua":    {{0, []byte{0x1B, 0x4C, 0x75, 0x61}, "Lua Bytecode"}},
	".dex":    {{0, []byte{0x64, 0x65, 0x78, 0x0A}, "Android DEX"}},
}

// textBasedExtensions holds extensions that don't have magic numbers (plain text formats)
var textBasedExtensions = map[string]string{
	".txt":  "Plain Text",
	".csv":  "CSV",
	".json": "JSON",
	".xml":  "XML",
	".html": "HTML",
	".htm":  "HTML",
	".css":  "CSS",
	".js":   "JavaScript",
	".ts":   "TypeScript",
	".go":   "Go Source",
	".py":   "Python Source",
	".rb":   "Ruby Source",
	".rs":   "Rust Source",
	".c":    "C Source",
	".cpp":  "C++ Source",
	".h":    "C Header",
	".java": "Java Source",
	".sh":   "Shell Script",
	".bat":  "Batch Script",
	".yaml": "YAML",
	".yml":  "YAML",
	".toml": "TOML",
	".ini":  "INI Config",
	".md":   "Markdown",
	".svg":  "SVG Image (XML-based)",
}

// color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func readFileBytes(path string, count int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, count)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

func matchesMagic(fileBytes []byte, sig MagicSignature) bool {
	end := sig.Offset + len(sig.Bytes)
	if end > len(fileBytes) {
		return false
	}
	for i, b := range sig.Bytes {
		if fileBytes[sig.Offset+i] != b {
			return false
		}
	}
	return true
}

func detectActualType(fileBytes []byte) (string, string) {
	for ext, sigs := range extensionMagicMap {
		for _, sig := range sigs {
			if matchesMagic(fileBytes, sig) {
				return ext, sig.Description
			}
		}
	}
	// Check if it's valid UTF-8 text
	isText := true
	for _, b := range fileBytes {
		if b < 0x09 || (b > 0x0D && b < 0x20 && b != 0x1B) {
			isText = false
			break
		}
	}
	if isText {
		return ".txt", "Plain Text (UTF-8)"
	}
	return "unknown", "Unknown Binary"
}

func checkFile(path string) {
	// Clean up path (trim whitespace and quotes)
	path = strings.TrimSpace(path)
	path = strings.Trim(path, `"'`)

	fmt.Println()
	fmt.Printf("%s%s Checking File %s\n")
	fmt.Printf("  Path      : %s\n", path)

	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("  %sError     : %s%s\n", colorRed, err.Error(), colorReset)
		return
	}
	fmt.Printf("  Size      : %d bytes\n", info.Size())

	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		fmt.Printf("  %sWarning   : File has no extension%s\n", colorYellow, colorReset)
		ext = "(none)"
	}
	fmt.Printf("  Extension : %s\n", ext)

	// --- Text-based extension check ---
	if desc, isText := textBasedExtensions[ext]; isText {
		fmt.Printf("  Claim     : %s\n", desc)
		fmt.Printf("  %s✓ Note%s     : '%s' is a text-based format with no magic number.\n", colorYellow, colorReset, ext)
		fmt.Printf("              Cannot verify content type via magic bytes, but file is readable as text.\n")
		return
	}

	// --- Magic number check ---
	sigs, known := extensionMagicMap[ext]
	if !known {
		fmt.Printf("  %s✗ Unknown%s  : Extension '%s' has no magic number mapping in this tool.\n", colorYellow, colorReset, ext)
	} else {
		fmt.Printf("  Claim     : %s\n", sigs[0].Description)
	}

	// Determine max bytes needed to read
	maxNeeded := 512 // default
	for _, sig := range sigs {
		if end := sig.Offset + len(sig.Bytes); end > maxNeeded {
			maxNeeded = end + 16
		}
	}
	if ext == ".tar" {
		maxNeeded = 512
	}
	if ext == ".iso" {
		maxNeeded = 32800
	}

	fileBytes, err := readFileBytes(path, maxNeeded)
	if err != nil {
		fmt.Printf("  %sError     : Failed to read file: %s%s\n", colorRed, err.Error(), colorReset)
		return
	}

	// Show first 16 bytes as hex
	preview := fileBytes
	if len(preview) > 16 {
		preview = preview[:16]
	}
	fmt.Printf("  Magic Hex : %s\n", strings.ToUpper(hex.EncodeToString(preview)))

	// Match claimed extension
	matched := false
	matchedDesc := ""
	if known {
		for _, sig := range sigs {
			if matchesMagic(fileBytes, sig) {
				matched = true
				matchedDesc = sig.Description
				break
			}
		}
	}

	// Detect what the file actually is
	actualExt, actualDesc := detectActualType(fileBytes)

	fmt.Println()
	if matched {
		fmt.Printf("  %s%sMATCH%s\n", colorBold, colorGreen, colorReset)
		fmt.Printf("  The file's magic bytes confirm it is a valid %s\n", matchedDesc)
	} else {
		fmt.Printf("  %s%sMISMATCH%s\n", colorBold, colorRed, colorReset)
		if known {
			fmt.Printf("  The extension claims '%s' but magic bytes do NOT match.\n", ext)
		}
		if actualExt != "unknown" && actualExt != ext {
			fmt.Printf("  Detected type : %s (%s)\n", actualDesc, actualExt)
			fmt.Printf("  %sThe file may have been renamed or is corrupted.%s\n", colorYellow, colorReset)
		} else if actualExt == "unknown" {
			fmt.Printf("  %sCould not identify the actual file type from its magic bytes.%s\n", colorYellow, colorReset)
		}
	}
}

func printBanner() {
	fmt.Println("  Paste a file path and press Enter to verify.")
	fmt.Println("  Type 'quit' or 'exit' to stop.")
	fmt.Println("  Type 'list' to see all supported extensions.")

}

func printSupportedList() {
	fmt.Println()
	fmt.Printf("%s%s  Supported Extensions with Magic Numbers:%s\n", colorBold, colorCyan, colorReset)

	categories := []struct {
		name string
		exts []string
	}{
		{"Images", []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tiff", ".psd"}},
		{"Documents", []string{".pdf", ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx", ".rtf"}},
		{"Archives", []string{".zip", ".gz", ".tar", ".bz2", ".7z", ".rar", ".zst", ".xz"}},
		{"Audio", []string{".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aiff"}},
		{"Video", []string{".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".webm", ".mpeg"}},
		{"Executables", []string{".exe", ".elf", ".dll", ".so", ".class", ".dex", ".wasm"}},
		{"Fonts", []string{".ttf", ".otf", ".woff", ".woff2"}},
		{"Database", []string{".sqlite", ".db"}},
		{"Other", []string{".iso", ".swf", ".lua", ".pyc"}},
	}

	for _, cat := range categories {
		fmt.Printf("\n  %s%s:%s ", colorBold, cat.name, colorReset)
		fmt.Println(strings.Join(cat.exts, "  "))
	}

	fmt.Println()
	fmt.Printf("%s%s  Text-Based (no magic number, always OK):%s\n", colorBold, colorYellow, colorReset)
	textExts := make([]string, 0, len(textBasedExtensions))
	for ext := range textBasedExtensions {
		textExts = append(textExts, ext)
	}
	fmt.Printf("  %s\n\n", strings.Join(textExts, "  "))
}

func main() {
	printBanner()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%sFile path%s » ", colorBold, colorReset)
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())

		switch strings.ToLower(input) {
		case "", " ":
			continue
		case "quit", "exit", "q":
			fmt.Println("\n  Goodbye!")
			return
		case "list":
			printSupportedList()
			continue
		}

		checkFile(input)
		fmt.Println()
	}
}
