"""Writes hand-made text in the double-byte East Asian code pages (encoded
with CPython's codecs): plain text in Shift_JIS, GBK, Big5 and EUC-KR,
which must be recognised as text in that code page, and an HTML page that
declares Shift_JIS.

Usage: python3 -I cjk.py <repo>/tests/fixtures/synthetic
"""

import os
import sys

OUT = sys.argv[1]


def write(fmt, name, data):
    path = os.path.join(OUT, fmt, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


JA = """これは日本語のテキストファイルです。
文字コードはシフトJISで保存されています。
昨日は雨が降っていましたが、今日はとても良い天気です。
駅の近くに新しい本屋ができたので、週末に行ってみようと思います。
このファイルは文字コードの判定を確認するために作られました。
"""
ZH_HANS = """这是一个用简体中文写的文本文件。
文件使用国标扩展编码保存。
今天天气很好，我们打算下午去公园散步。
学习一门新的语言需要时间和耐心，但是非常有意思。
这个文件是为了测试字符编码的识别而生成的。
"""
ZH_HANT = """這是一個用繁體中文寫的文字檔案。
檔案使用大五碼保存。
今天天氣很好，我們打算下午去公園散步。
學習一門新的語言需要時間和耐心，但是非常有意思。
這個檔案是為了測試字元編碼的識別而產生的。
"""
KO = """이것은 한국어로 쓴 텍스트 파일입니다.
파일은 완성형 한글 코드로 저장되어 있습니다.
어제는 비가 많이 왔지만 오늘은 날씨가 아주 좋습니다.
새로운 언어를 배우는 것은 시간이 걸리지만 정말 재미있습니다.
이 파일은 문자 인코딩 판별을 확인하기 위해 만들었습니다.
"""

write("text", "shift_jis.txt", JA.encode("cp932"))
write("text", "gbk.txt", ZH_HANS.encode("gbk"))
write("text", "big5.txt", ZH_HANT.encode("cp950"))
write("text", "euc-kr.txt", KO.encode("cp949"))
write("html", "shift_jis.html", ("""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="Shift_JIS">
<title>日本語のページ</title>
</head>
<body>
<p>""" + JA.replace("\n", "<br>\n") + """</p>
</body>
</html>
""").encode("cp932"))
