// Command syncbuild 把 wails 的构建产物同步一份到项目根目录。
//
// 由 wails.json 的 postBuildHooks 调用（工作目录是 build/bin，并传入 ${bin}）。
//
// 为什么不用现成的命令：
//   - xcopy：目标文件不存在时会交互式追问「是文件名还是目录名」，会把构建永久挂住；
//   - robocopy：成功时退出码是 1，wails 会把它当成构建失败；
//   - copy / cp：前者是 cmd 内建命令、后者在 Windows 上不保证在 PATH 里。
//
// 用法：syncbuild [<已构建的可执行文件路径>]
// 不传参数时按 build/bin/<name> 推断。
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const binaryName = "KNcloud-WIN.exe"

func main() {
	if err := run(); err != nil {
		// 必须让 wails 看到非零退出码：它只在 hook 失败时打印 stderr，
		// 成功时连 stdout 都只在 -v 下才显示。退出 0 的话这个警告会被吞掉，
		// 用户就会拿着旧的根目录副本去跑，还以为测过了新构建。
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "syncbuild: 同步到项目根目录失败（编译本身是成功的，产物在 build/bin 里）")
		fmt.Fprintln(os.Stderr, "syncbuild:", err)
		fmt.Fprintln(os.Stderr, "syncbuild: 目标多半正被运行中的 KNcloud-WIN 占用。退出程序后重新构建，")
		fmt.Fprintln(os.Stderr, "syncbuild: 或单独执行：go run tools/syncbuild build/bin/KNcloud-WIN.exe")
		fmt.Fprintln(os.Stderr, "")
		os.Exit(1)
	}
}

func run() error {
	src := os.Args[1:]
	var binPath string
	if len(src) > 0 && src[0] != "" {
		binPath = src[0]
	} else {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		binPath = filepath.Join(wd, binaryName)
	}
	absBin, err := filepath.Abs(binPath)
	if err != nil {
		return err
	}

	st, err := os.Stat(absBin)
	if err != nil {
		return fmt.Errorf("built binary not found: %w", err)
	}

	// <项目根>/build/bin/KNcloud-WIN.exe -> <项目根>/KNcloud-WIN.exe
	root := filepath.Dir(filepath.Dir(filepath.Dir(absBin)))
	dst := filepath.Join(root, filepath.Base(absBin))
	if dst == absBin {
		return nil
	}

	// 先写临时文件再改名：避免复制到一半被中断，留下半个可执行文件。
	tmp := dst + ".tmp"
	if err := copyFile(absBin, tmp); err != nil {
		return err
	}
	if err := replaceFile(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	fmt.Printf("syncbuild: %s -> %s (%d bytes)\n", filepath.Base(absBin), dst, st.Size())
	return nil
}

// replaceFile 用 tmp 覆盖 dst。
//
// 目标很可能是正在运行的 exe：Windows 允许「删除」正在运行的映像（进入
// delete-pending，老进程继续用内存里的旧映像），但不允许 MoveFileEx 直接
// 覆盖它（报 Access is denied）。所以先试改名，失败再退化成先删后改名。
func replaceFile(tmp, dst string) error {
	err := os.Rename(tmp, dst)
	if err == nil {
		return nil
	}
	if rmErr := os.Remove(dst); rmErr != nil && !os.IsNotExist(rmErr) {
		return fmt.Errorf("cannot replace %s (is the app still running?): %w", dst, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("replaced %s but failed to move the new binary into place: %w", dst, err)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
