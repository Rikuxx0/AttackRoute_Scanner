# AttackRoute_Scanner
本ツールは、Draw.io で定義されたシステム構造と、Nuclei/Nikto による脆弱性診断結果を自動統合し、
攻撃チェーン・ノード特性・リスクスコアを一括可視化するための PoC です。

- 攻撃経路を NetworkX + PyVis で自動推論
- ノードごとの脆弱性数・Severity・重要度・proximity を統合
- リスクスコアを算出し可視化

## 処理フロー
1. Draw.io → parse_drawio_html　→ drawioのアーキテクチャの解析後データ
2. Nuclei/Nikto → parse_vuln → manual_mapping → 脆弱性診断のレポートの解析データ
3. drawioのアーキテクチャの解析後データ、脆弱性診断のレポートの解析データの統合 → networkx_core → risk_calc → Streamlit 可視化

# 使い方
1. Draw.io の HTML を export してアップロード
2. Nuclei/Nikto の TXT レポートを複数アップロード
3. manual_mapping.jsonにdrawio上でのサービス名と実際のホスト名を記述し、アップロード
4. Streamlit 上で自動解析開始
5. 攻撃チェーンとリスクスコアが自動表示される

```
# コマンドで実行 (ローカル)
streamlit run app.py
```

manual_mapping.jsonの記述例
```
{
  "vuln-api": "localhost:5000",
  "OWASP juice-shop": "localhost:3000"
}
```


JSON出力結果のサンプル例
```
{
  "label": "vuln-api",
  "Vuln_Count": 12,
  "Severity": 2.3,
  "proximity": 0.52,
  "Importance": 2.0,
  "Risk_Score": 24.96
}
```