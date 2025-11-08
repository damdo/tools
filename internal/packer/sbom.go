package packer

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/gokrazy/internal/config"
	"github.com/gokrazy/tools/internal/buildid"
	"github.com/gokrazy/tools/packer"
	"golang.org/x/mod/modfile"
	"golang.org/x/sync/errgroup"
)

type FileHash struct {
	// Path is relative to the gokrazy instance directory (or absolute).
	Path string `json:"path"`

	// Hash is the SHA256 sum of the file.
	Hash string `json:"hash"`
}

// GoPackage identifies a built Go binary via its BuildInfo (human readable) and
// BuildID. When installing a non-local package, the BuildInfo will be
// sufficient to reproduce exactly this binary. For local packages, any change
// to the source will just show up as (dirty) in BuildInfo, so we record the
// BuildID in addition, which will change whenever the source changes.
type GoPackage struct {
	// Path is an absolute path on the gokrazy instance, e.g. /gokrazy/init
	Path string `json:"path"`

	// BuildID contains the Go (or GNU) build ID.
	BuildID string

	// BuildInfo contains the String representation of debug.BuildInfo
	BuildInfo string
}

// SystemPackage identifies non-Go system packages (kernel, firmware, EEPROM)
// by their module path, version, and the hashes of their binary files.
type SystemPackage struct {
	// ModulePath is the Go module path (e.g., github.com/gokrazy/kernel)
	ModulePath string `json:"module_path"`

	// Version is the module version from go.mod
	Version string `json:"version"`

	// FileHashes contains hashes of the actual binary files provided by this package
	FileHashes []FileHash `json:"file_hashes"`
}

type SBOM struct {
	// ConfigHash is the SHA256 sum of the gokrazy instance config (loaded
	// from config.json).
	ConfigHash FileHash `json:"config_hash"`

	// ExtraFileHashes is list of FileHashes, sorted by path.
	//
	// It contains one entry for each file referenced via ExtraFilePaths:
	// https://gokrazy.org/userguide/instance-config/#packageextrafilepaths
	ExtraFileHashes []FileHash `json:"extra_file_hashes"`

	// GoPackages contains one entry per installed package of the gokrazy
	// instance.
	GoPackages []GoPackage `json:"go_packages"`

	// SystemPackages contains entries for kernel, firmware, and EEPROM packages.
	SystemPackages []SystemPackage `json:"system_packages"`
}

type SBOMWithHash struct {
	SBOMHash string `json:"sbom_hash"`
	SBOM     SBOM   `json:"sbom"`
}

func readBuildID(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	const readSize = 32 * 1024
	data := make([]byte, readSize)
	_, err := io.ReadFull(f, data)
	if err == io.ErrUnexpectedEOF {
		err = nil
	}
	if err != nil {
		return "", err
	}
	return buildid.ReadELF(f.Name(), f, data)
}

// generateSBOM generates a Software Bills Of Material (SBOM) for the
// local gokrazy instance.
// It must be provided with a cfg that hasn't been modified by gok at runtime,
// as the SBOM should reflect what’s going into gokrazy,
// not its internal implementation details
// (i.e.  cfg.InternalCompatibilityFlags untouched).
func generateSBOM(cfg *config.Struct, foundBins []foundBin) ([]byte, SBOMWithHash, error) {
	instancePath, err := os.Getwd()
	if err != nil {
		return nil, SBOMWithHash{}, err
	}
	defer os.Chdir(instancePath)

	formattedCfg, err := cfg.FormatForFile()
	if err != nil {
		return nil, SBOMWithHash{}, err
	}

	result := SBOM{
		ConfigHash: FileHash{
			Path: config.InstanceConfigPath(),
			Hash: fmt.Sprintf("%x", sha256.Sum256([]byte(string(formattedCfg)))),
		},
	}

	var (
		eg           errgroup.Group
		goPackagesMu sync.Mutex
	)
	for _, bin := range foundBins {
		eg.Go(func() error {
			f, err := os.Open(bin.hostPath)
			if err != nil {
				return err
			}
			info, err := buildinfo.Read(f)
			if err != nil {
				return err
			}
			id, err := readBuildID(f)
			if err != nil {
				return err
			}

			goPackagesMu.Lock()
			defer goPackagesMu.Unlock()
			result.GoPackages = append(result.GoPackages, GoPackage{
				Path:      bin.gokrazyPath,
				BuildID:   id,
				BuildInfo: info.String(),
			})
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, SBOMWithHash{}, err
	}

	// Track system packages (e.g. kernel, firmware, EEPROM)
	systemPkgs := []string{cfg.KernelPackageOrDefault()}
	if fw := cfg.FirmwarePackageOrDefault(); fw != "" {
		systemPkgs = append(systemPkgs, fw)
	}
	if e := cfg.EEPROMPackageOrDefault(); e != "" {
		systemPkgs = append(systemPkgs, e)
	}

	for _, pkgPath := range systemPkgs {
		sysPkg, err := generateSystemPackage(cfg, pkgPath)
		if err != nil {
			return nil, SBOMWithHash{}, fmt.Errorf("system package %s: %w", pkgPath, err)
		}
		if sysPkg != nil {
			result.SystemPackages = append(result.SystemPackages, *sysPkg)
		}
	}

	extraFiles, err := FindExtraFiles(cfg)
	if err != nil {
		return nil, SBOMWithHash{}, err
	}

	packages := append(getGokrazySystemPackages(cfg), cfg.Packages...)

	for _, pkgAndVersion := range packages {
		pkg := pkgAndVersion
		if idx := strings.IndexByte(pkg, '@'); idx > -1 {
			pkg = pkg[:idx]
		}

		files := append([]*FileInfo{}, extraFiles[pkg]...)
		if len(files) == 0 {
			continue
		}

		for len(files) > 0 {
			fi := files[0]
			files = files[1:]
			files = append(files, fi.Dirents...)
			if fi.FromHost == "" {
				// Files that are not copied from the host are contained
				// fully in the config, which we already hashed.
				continue
			}

			b, err := os.ReadFile(fi.FromHost /* already absolute */)
			if err != nil {
				return nil, SBOMWithHash{}, err
			}
			result.ExtraFileHashes = append(result.ExtraFileHashes, FileHash{
				Path: fi.FromHost,
				Hash: fmt.Sprintf("%x", sha256.Sum256(b)),
			})
		}
	}

	sort.Slice(result.GoPackages, func(i, j int) bool {
		pi := result.GoPackages[i]
		pj := result.GoPackages[j]
		return pi.Path < pj.Path
	})

	sort.Slice(result.SystemPackages, func(i, j int) bool {
		return result.SystemPackages[i].ModulePath < result.SystemPackages[j].ModulePath
	})

	sort.Slice(result.ExtraFileHashes, func(i, j int) bool {
		a := result.ExtraFileHashes[i]
		b := result.ExtraFileHashes[j]
		return a.Path < b.Path
	})

	b, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		return nil, SBOMWithHash{}, err
	}
	b = append(b, '\n')

	sH := SBOMWithHash{
		SBOMHash: fmt.Sprintf("%x", sha256.Sum256(b)),
		SBOM:     result,
	}

	sM, err := json.MarshalIndent(sH, "", "    ")
	if err != nil {
		return nil, SBOMWithHash{}, err
	}
	sM = append(sM, '\n')

	return sM, sH, nil
}

func generateSystemPackage(cfg *config.Struct, pkgPath string) (*SystemPackage, error) {
	// Strip version suffix if present
	pkg := pkgPath
	if idx := strings.IndexByte(pkg, '@'); idx > -1 {
		pkg = pkg[:idx]
	}

	// Get the package directory
	pkgDir, err := packer.PackageDir(pkgPath)
	if err != nil {
		return nil, err
	}

	// Read go.mod to get module path and version
	goModPath := filepath.Join(pkgDir, "go.mod")
	goModBytes, err := os.ReadFile(goModPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If there's no go.mod, skip this package
			return nil, nil
		}
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	modf, err := modfile.Parse("go.mod", goModBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	sysPkg := &SystemPackage{
		ModulePath: modf.Module.Mod.Path,
		Version:    modf.Module.Mod.Version,
	}

	// If version is empty (happens for local modules), try to extract from package path
	if sysPkg.Version == "" && strings.Contains(pkgPath, "@") {
		parts := strings.SplitN(pkgPath, "@", 2)
		if len(parts) == 2 {
			sysPkg.Version = parts[1]
		}
	}

	// Hash binary files in the package directory
	// For kernel packages, look for vmlinuz, bzImage, kernel files
	// For firmware/EEPROM, hash all binary files
	err = filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip hidden directories and typical non-binary directories
			if strings.HasPrefix(info.Name(), ".") || info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip text files and Go source
		ext := filepath.Ext(path)
		if ext == ".go" || ext == ".mod" || ext == ".sum" || ext == ".txt" || ext == ".md" {
			return nil
		}

		// Read and hash the file
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Only include files that are likely binaries (non-empty and not tiny text files)
		if len(data) > 0 {
			relPath, err := filepath.Rel(pkgDir, path)
			if err != nil {
				relPath = path
			}
			sysPkg.FileHashes = append(sysPkg.FileHashes, FileHash{
				Path: relPath,
				Hash: fmt.Sprintf("%x", sha256.Sum256(data)),
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking package directory: %w", err)
	}

	// Sort file hashes for consistent output
	sort.Slice(sysPkg.FileHashes, func(i, j int) bool {
		return sysPkg.FileHashes[i].Path < sysPkg.FileHashes[j].Path
	})

	return sysPkg, nil
}

func getGokrazySystemPackages(cfg *config.Struct) []string {
	pkgs := append([]string{}, cfg.GokrazyPackagesOrDefault()...)
	pkgs = append(pkgs, packer.InitDeps(cfg.InternalCompatibilityFlags.InitPkg)...)
	pkgs = append(pkgs, cfg.KernelPackageOrDefault())
	if fw := cfg.FirmwarePackageOrDefault(); fw != "" {
		pkgs = append(pkgs, fw)
	}
	if e := cfg.EEPROMPackageOrDefault(); e != "" {
		pkgs = append(pkgs, e)
	}
	return pkgs
}
