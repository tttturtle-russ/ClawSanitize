package parser

import (
	"os"
	"path/filepath"
	"strings"
)

var codeExtensions = map[string]bool{
	".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".py": true, ".rb": true, ".go": true, ".sh": true,
	".bash": true, ".zsh": true, ".fish": true,
	".mjs": true, ".cjs": true,
}

type SkillFile struct {
	Path    string
	Name    string
	Content string
}

type InstalledSkill struct {
	Slug      string
	SkillMD   *SkillFile
	CodeFiles []SkillFile
	License   *SkillFile
}

func ParseSkillFiles(installRoot string) ([]InstalledSkill, error) {
	if strings.HasPrefix(installRoot, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		installRoot = filepath.Join(home, installRoot[2:])
	}

	skillsRoot := filepath.Join(installRoot, "skills")

	dirs, err := os.ReadDir(skillsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []InstalledSkill
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		slug := d.Name()
		skillDir := filepath.Join(skillsRoot, slug)
		skill := InstalledSkill{Slug: slug}
		entries, err := os.ReadDir(skillDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			absPath := filepath.Join(skillDir, name)
			content := readFileOrEmpty(absPath)
			f := SkillFile{Path: absPath, Name: name, Content: content}
			switch {
			case strings.EqualFold(name, "SKILL.md"):
				skill.SkillMD = &SkillFile{Path: absPath, Name: name, Content: content}
			case strings.EqualFold(name, "LICENSE") || strings.EqualFold(name, "LICENSE.md") || strings.EqualFold(name, "LICENSE.txt"):
				skill.License = &f
			default:
				ext := strings.ToLower(filepath.Ext(name))
				if codeExtensions[ext] {
					skill.CodeFiles = append(skill.CodeFiles, f)
				}
			}
		}
		result = append(result, skill)
	}
	return result, nil
}
