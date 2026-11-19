/**
 * Chrome Built-in AI (On-Device Gemini Nano) 하이브리드 헬퍼
 * - Chrome 138+ 데스크톱의 Summarizer API / Prompt API (LanguageModel)를 우선 활용하고,
 *   미지원 환경에서는 안전하게 null을 반환하여 기존 백엔드 API로 Fallback합니다.
 */
(function (global) {
  const PROMPT_IO_OPTIONS = {
    expectedOutputs: [{ type: "text", languages: ["en"] }]
  };

  const SUMMARIZER_OPTIONS = {
    type: "key-points",
    format: "plain-text",
    length: "short",
    outputLanguage: "en"
  };

  const LocalAI = {
    async getCapabilities() {
      const result = {
        promptApi: "unavailable",
        summarizerApi: "unavailable"
      };

      try {
        if ("LanguageModel" in self && typeof self.LanguageModel.availability === "function") {
          result.promptApi = await self.LanguageModel.availability(PROMPT_IO_OPTIONS);
        }
      } catch (_) {}

      try {
        if ("Summarizer" in self && typeof self.Summarizer.availability === "function") {
          result.summarizerApi = await self.Summarizer.availability(SUMMARIZER_OPTIONS);
        }
      } catch (_) {}

      return result;
    },

    /**
     * 드래그 텍스트를 온디바이스 Gemini Nano로 초고속 1차 스크리닝합니다.
     * - Chrome Built-in AI 지원 출력 언어([de, en, es, fr, ja]) 규격을 준수해 en으로 JSON 판정만 받고,
     *   명백히 안전하면 한국어 안전 안내를 즉시 표시합니다.
     * - 의심스럽거나 판정이 모호하면 needs_escalation: true로 백엔드 RAG/Cloud Gemini에 넘깁니다.
     */
    async screenTextLocally(selectedText) {
      try {
        if (!("LanguageModel" in self) || typeof self.LanguageModel.availability !== "function") {
          return null;
        }
        const avail = await self.LanguageModel.availability(PROMPT_IO_OPTIONS);
        if (avail !== "available" && avail !== "readily") {
          return null;
        }

        const session = await self.LanguageModel.create({
          ...PROMPT_IO_OPTIONS,
          initialPrompts: [
            {
              role: "system",
              content:
                "You are a strict on-device phishing & smishing screener. " +
                "Respond ONLY with valid JSON: " +
                '{"risk_score": 0-100, "needs_escalation": boolean}. ' +
                "Set needs_escalation=true if there is ANY hint of phishing, urgency, account verification, " +
                "delivery scam, family impersonation, financial request, suspicious link, or uncertainty. " +
                "Only set needs_escalation=false and risk_score<=20 for clearly benign everyday text."
            }
          ]
        });

        try {
          const raw = await session.prompt(
            `Screen this text for phishing/smishing/social-engineering intent and reply with JSON only:\n"${selectedText.slice(0, 500)}"`
          );
          const cleaned = String(raw || "").replace(/```json/g, "").replace(/```/g, "").trim();
          const start = cleaned.indexOf("{");
          const end = cleaned.lastIndexOf("}");
          if (start === -1 || end === -1) return null;

          const parsed = JSON.parse(cleaned.slice(start, end + 1));
          const riskScore = Math.max(0, Math.min(100, Number(parsed.risk_score ?? 50)));
          return {
            risk_score: riskScore,
            needs_escalation: Boolean(parsed.needs_escalation) || riskScore > 20,
            reason: "온디바이스 AI(Gemini Nano) 1차 검사 결과 사기·피싱 징후가 없는 일상 문구로 확인되었습니다.",
            mitigation: "안심하고 확인하세요.",
            engine: "chrome-built-in-ai"
          };
        } finally {
          if (session && typeof session.destroy === "function") {
            session.destroy();
          }
        }
      } catch (err) {
        console.debug("[LocalAI] Prompt API 사용 불가, 백엔드로 전환:", err);
        return null;
      }
    },

    /**
     * Chrome Built-in Summarizer API로 이메일 본문을 로컬 요약합니다.
     */
    async summarizeEmailLocally(emailText) {
      try {
        if (!emailText || emailText.trim().length < 30) return null;
        if (!("Summarizer" in self) || typeof self.Summarizer.availability !== "function") {
          return null;
        }
        const avail = await self.Summarizer.availability(SUMMARIZER_OPTIONS);
        if (avail !== "available" && avail !== "readily") {
          return null;
        }

        const summarizer = await self.Summarizer.create(SUMMARIZER_OPTIONS);

        try {
          const summary = await summarizer.summarize(emailText.slice(0, 4000));
          return summary ? summary.trim() : null;
        } finally {
          if (summarizer && typeof summarizer.destroy === "function") {
            summarizer.destroy();
          }
        }
      } catch (err) {
        console.debug("[LocalAI] Summarizer API 사용 불가:", err);
        return null;
      }
    }
  };

  global.LocalAI = LocalAI;
})(window);
