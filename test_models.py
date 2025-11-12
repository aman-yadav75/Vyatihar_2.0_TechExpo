import google.generativeai as genai

# 🔑 Use your Gemini API key
genai.configure(api_key="AIzaSyAexFGgmt_7ybToirJ_oI4MXwADkcbTqlA")

print("\n📋 Available models for your Gemini key:\n")
for m in genai.list_models():
    print("➡️", m.name)
