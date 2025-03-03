import "pe"

rule malw_14a388b154b55a25c66b1bfef9499b64 {
    meta:
        description = "file 14a388b154b55a25c66b1bfef9499b64"
        author = "ino"
        date = "March 2025"
    strings:
        $x = "@@DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" ascii
        
}