package process

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-tun"
)

var _ Searcher = (*androidSearcher)(nil)

type androidSearcher struct {
	packageManager tun.PackageManager
}

func NewSearcher(config Config) (Searcher, error) {
	return &androidSearcher{config.PackageManager}, nil
}

func (s *androidSearcher) FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*Info, error) {
	inode, uid, err := resolveSocketByNetlink(network, source, destination)
	if err != nil {
		return nil, err
	}
	info := Info{
		UserId: int32(uid),
	}
	if processPath, _ := resolveProcessNameByProcSearch(inode, uid); processPath != "" {
		info.ProcessPath = processPath
		if s.packageManager != nil {
			if _, loaded := s.packageManager.IDByPackage(processPath); loaded {
				info.PackageName = processPath
			}
		}
	} else if s.packageManager != nil {
		if sharedPackage, loaded := s.packageManager.SharedPackageByID(uid % 100000); loaded {
			info.PackageName = sharedPackage
		} else if packageName, loaded := s.packageManager.PackageByID(uid % 100000); loaded {
			info.PackageName = packageName
		}
	}
	return &info, nil
}
