#!/bin/bash
# 搜尋手寫文字辨識相關的 skills

echo "搜尋關鍵字: handwriting ocr"
npx -y @lobehub/market-cli skills search --q "handwriting ocr" --page-size 10

echo ""
echo "搜尋關鍵字: handwritten recognition"
npx -y @lobehub/market-cli skills search --q "handwritten recognition" --page-size 10

echo ""
echo "搜尋關鍵字: OCR text recognition"
npx -y @lobehub/market-cli skills search --q "OCR text recognition" --page-size 10
