import streamlit as st
import google.generativeai as genai
import os
from dotenv import load_dotenv

# --- Configuration ---
# .envファイルから環境変数を読み込み、Streamlitのsecretsにもフォールバックします。

def get_gemini_api_key():
    """
    Gets the Gemini API key from .env file, environment variable, or Streamlit secrets.
    """
    # .envファイルから環境変数を読み込む
    load_dotenv()

    # 1. 環境変数から取得を試みる（.envファイルから読み込まれた値を含む）
    api_key = os.environ.get("GEMINI_API_KEY")
    if api_key:
        return api_key
    
    # 2. Streamlit secretsからの取得を試みる（フォールバック）
    try:
        return st.secrets["GEMINI_API_KEY"]
    except (KeyError, FileNotFoundError):
        st.error("Gemini APIキーが見つかりません。.envファイル、環境変数、またはStreamlit secretsに設定してください。")
        st.info("設定方法: .envファイルに `GEMINI_API_KEY=your_key` を追加するか、secrets.tomlファイルに `GEMINI_API_KEY = \"your_key\"` を追加してください。")
        return None


def generate_risk_assessment_from_reports(path_node_scores, all_report_texts):
    """
    Generates a risk assessment by providing the full context of vulnerability reports and risk scores to the Gemini API.

    Args:
        path_node_scores (list): A list of dicts, each containing 'label' and 'Risk_Score' for a node in the path.
        all_report_texts (list): A list of strings, where each string is the content of a vuln report.

    Returns:
        A string containing the generated explanation, or an error message.
    """

    api_key = get_gemini_api_key()
    if not api_key:
        return "APIキーが設定されていません。"

    # Check for empty context to avoid unnecessary API calls
    if not path_node_scores and not all_report_texts:
        return "解説を生成するための情報(攻撃パスと脆弱性レポート)がありません。"

    genai.configure(api_key=api_key)
    
    # モデルの設定
    model = genai.GenerativeModel('gemini-2.5-flash')

    # --- Build the Prompt ---
    prompt_header = """
あなたは優秀なセキュリティアナリストであり、オフェンシブセキュリティの知識を持つペネトレーションテスターです。
以下の情報に基づき、検出された攻撃パス(攻撃チェーン)が、実際にどのような脅威となりうるかを分析し、その攻撃シナリオを具体的に説明してください。

**考慮すべき情報:**
1.  **検出された攻撃パスと各ノードのリスクスコア:** 分析の起点となる、特に注目すべき一連のステップです。各ノードに割り当てられたリスクスコアも重要な判断材料です。スコアが高いほど、そのノードは攻撃者にとって価値が高いか、あるいは侵害されやすいことを示します。
2.  **脆弱性レポート全文:** システム全体に存在する可能性のある、全ての脆弱性情報です。

**説明の手順:**

*   まず、提示された「攻撃パス」に沿って攻撃が成立する可能性が最も高いクリティカルなシナリオを、「リスクスコア」と「脆弱性レポート」の内容を関連付けながら具体的に説明してください。特にリスクスコアが高いノードに注目してください。
*   次に、攻撃パスとは直接関係ない脆弱性も含め、「脆弱性レポート全文」から読み取れる他の攻撃シナリオや潜在的なリスクを簡潔に説明してください。
*   現実的な攻撃シナリオがある場合、各攻撃シナリオごとに再現手順を1,2,3...のように数字を使って説明しなさい。
*   最終的に、このシステム全体が直面している最も大きな脅威は何か、そして最悪の場合どのような事態が想定されるかを結論として述べてください。

**説明のポイント:**

*   リスクスコア(Risk_Score)が0に近い数値である場合、攻撃成立の可能性として低く、攻撃者が目標を達成するのは困難であるため、もし脆弱性レポートでリスクスコア(Risk_Score)が0に近い数値であった時は潜在的な脆弱性として扱うようにしてください。
*   出力はMarkdown形式で、重要な箇所は太字で強調してください。
*   説明は簡潔に答えてください。
*   専門用語を避け、誰にでも危険性が一目で理解できる簡単な言葉で説明してください。


"""
    
    # 攻撃パスとリスクスコアの文字列を生成
    path_with_scores_str = "\n".join([f"- `{node['label']}` (リスクスコア: **{node['Risk_Score']}**)" for node in path_node_scores])
    
    # 脆弱性レポートのリストを一つのテキストブロックに結合
    reports_str = "\n\n---(次のレポート)---\n\n".join(all_report_texts)

    prompt_context = f"""
---
### **分析対象のコンテキスト**

**1. 検出された攻撃パスと各ノードのリスクスコア:**
{path_with_scores_str}

**2. 脆弱性レポート全文:**
```text
{reports_str}
```
---
"""

    # 回答作成
    final_prompt = prompt_header + prompt_context
    # st.text_area("Final Prompt to AI", final_prompt, height=300) # DEBUG: Show final prompt

    # --- Generate Content ---
    try:
        result = model.generate_content(final_prompt)
        res_content = result.text
        return res_content
    except Exception as e:
        st.error(f"リスク評価でエラーが発生しました: {e}")
        # st.exception(e) # Display the full stack trace for debugging
        return "解説の生成に失敗しました。詳細は上記のエラーメッセージを確認してください。"