package main

import (
    "bufio"
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha256"
    "encoding/base64"
    "flag"
    "fmt"
    "os"
    "strconv"
    "strings"
)

func sha256Bytes(s string) []byte {
    h := sha256.Sum256([]byte(s))
    return h[:]
}

func pkcs7(data []byte, bs int) []byte {
    pad := bs - (len(data) % bs)
    if pad == 0 {
        pad = bs
    }
    out := make([]byte, len(data)+pad)
    copy(out, data)
    for i := len(data); i < len(out); i++ {
        out[i] = byte(pad)
    }
    return out
}

func ab2b64(b []byte) string {
    return base64.StdEncoding.EncodeToString(b)
}

func pickAlphaNum(s string, startIdx int) byte {
    n := len(s)
    for k := 0; k < n; k++ {
        ch := s[(startIdx+k)%n]
        if (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
            return ch
        }
    }
    return '0'
}

func encTail(first10 string) (string, error) {
    keyBytes := sha256Bytes("123456")
    block, err := aes.NewCipher(keyBytes)
    if err != nil {
        return "", err
    }
    iv := sha256Bytes(first10)[:16]
    data := pkcs7([]byte(first10), block.BlockSize())
    cipherText := make([]byte, len(data))
    cipher.NewCBCEncrypter(block, iv).CryptBlocks(cipherText, data)
    b64 := ab2b64(cipherText)
    positions := []int{1, 3, 6, 10, 15, 21}
    out := make([]byte, 6)
    for i, p := range positions {
        out[i] = pickAlphaNum(b64, p-1)
    }
    return strings.ToUpper(string(out)), nil
}

func buildFirst10(t, m string, sn int) (string, error) {
    tl := len(t)
    ml := len(m)
    remain := 10 - (tl + ml)
    if remain < 1 {
        return "", fmt.Errorf("前10位长度不合法：产品类型+型号总长度需小于10")
    }
    snStr := fmt.Sprintf("%0*d", remain, sn)
    return t + m + snStr, nil
}

type Row struct {
    Idx   int
    Type  string
    Model string
    SN    int
    F10   string
    Tail6 string
    DID   string
}

func generateRows(t, m string, snStart, count int) ([]Row, error) {
    rows := make([]Row, 0, count)
    for i := 0; i < count; i++ {
        sn := snStart + i
        f10, err := buildFirst10(t, m, sn)
        if err != nil {
            return rows, err
        }
        tail6, err := encTail(f10)
        if err != nil {
            return rows, err
        }
        did := f10 + tail6
        rows = append(rows, Row{Idx: i + 1, Type: t, Model: m, SN: sn, F10: f10, Tail6: tail6, DID: did})
    }
    return rows, nil
}

func writeXls(rows []Row, name string) error {
    if name == "" {
        name = "did_list.xls"
    }
    f, err := os.Create(name)
    if err != nil {
        return err
    }
    defer f.Close()
    w := bufio.NewWriter(f)
    defer w.Flush()
    head := []string{"#", "产品类型", "型号", "SN", "First10", "尾6", "DID"}
    fmt.Fprintf(w, "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body><table border=\"1\"><thead><tr>")
    for _, h := range head {
        fmt.Fprintf(w, "<th>%s</th>", h)
    }
    fmt.Fprintf(w, "</tr></thead><tbody>")
    for _, r := range rows {
        fmt.Fprintf(w, "<tr>")
        fmt.Fprintf(w, "<td>%d</td>", r.Idx)
        fmt.Fprintf(w, "<td>%s</td>", r.Type)
        fmt.Fprintf(w, "<td>%s</td>", r.Model)
        fmt.Fprintf(w, "<td>%d</td>", r.SN)
        fmt.Fprintf(w, "<td>%s</td>", r.F10)
        fmt.Fprintf(w, "<td>%s</td>", r.Tail6)
        fmt.Fprintf(w, "<td>%s</td>", r.DID)
        fmt.Fprintf(w, "</tr>")
    }
    fmt.Fprintf(w, "</tbody></table></body></html>")
    return nil
}

func main() {
    t := flag.String("type", "", "产品类型，如 PT")
    m := flag.String("model", "", "型号，如 MD100")
    snStart := flag.Int("snStart", 1, "起始SN")
    count := flag.Int("count", 1, "生成数量")
    file := flag.String("out", "did_list.xls", "导出文件名")
    preview := flag.Int("preview", 10, "控制台预览条数")
    flag.Parse()

    rows, err := generateRows(*t, *m, *snStart, *count)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    n := *preview
    if n > len(rows) {
        n = len(rows)
    }
    fmt.Println("#\t类型\t型号\tSN\tFirst10\t尾6\tDID")
    for i := 0; i < n; i++ {
        r := rows[i]
        fmt.Println(strconv.Itoa(r.Idx) + "\t" + r.Type + "\t" + r.Model + "\t" + strconv.Itoa(r.SN) + "\t" + r.F10 + "\t" + r.Tail6 + "\t" + r.DID)
    }
    if err := writeXls(rows, *file); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(2)
    }
    fmt.Println("导出完成:", *file)
}
