import 'dotenv/config';
import express, { type Request, type Response, type NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { GoogleGenAI, Type, ThinkingLevel, type FunctionDeclaration } from '@google/genai';
import { WebSocketServer, type WebSocket } from 'ws';
import { initializeApp as initializeAdminApp, getApps as getAdminApps } from 'firebase-admin/app';
import { getAuth as getAdminAuth } from 'firebase-admin/auth';
import mammoth from 'mammoth';
import { PDFParse } from 'pdf-parse';
import JSZip from 'jszip';
import {
  AlignmentType,
  BorderStyle,
  Document,
  Footer,
  Header,
  Packer,
  PageNumber,
  Paragraph,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from 'docx';

const PORT = 3000;
const OWNER_EMAIL = 'am0502881@gmail.com';

interface FirebaseConfigFile {
  projectId: string;
  apiKey: string;
  firestoreDatabaseId: string;
}

const firebaseConfig: FirebaseConfigFile = JSON.parse(
  fs.readFileSync(path.resolve(process.cwd(), 'firebase-applet-config.json'), 'utf8')
);

const adminApp =
  getAdminApps().length > 0
    ? getAdminApps()[0]
    : initializeAdminApp({ projectId: firebaseConfig.projectId });
const adminAuth = getAdminAuth(adminApp);

const SEAL_KEY = crypto
  .createHash('sha256')
  .update(
    process.env.EXAM_SEAL_SECRET ||
      `${firebaseConfig.projectId}:${firebaseConfig.firestoreDatabaseId}:mr-ahmed-aboo-seal-2026`
  )
  .digest();

function getGeminiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    throw new Error('GEMINI_API_KEY_MISSING');
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

interface VerifiedUser {
  uid: string;
  email: string;
  emailVerified: boolean;
  isOwner: boolean;
}

interface AuthenticatedRequest extends Request {
  authUser?: VerifiedUser;
}

async function verifyFirebaseBearer(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'يرجى تسجيل الدخول أولاً للوصول إلى هذه الخدمة.' });
    return;
  }
  const token = authHeader.slice(7).trim();
  try {
    const decoded = await adminAuth.verifyIdToken(token);
    const email = (decoded.email || '').toLowerCase();
    const emailVerified = Boolean(decoded.email_verified);
    req.authUser = {
      uid: decoded.uid,
      email,
      emailVerified,
      isOwner: email === OWNER_EMAIL && emailVerified,
    };
    next();
  } catch (err) {
    console.error('Firebase token verification failed:', err);
    res.status(401).json({ error: 'انتهت صلاحية الجلسة أو الرمز غير صالح.' });
  }
}

async function verifyTeacherViaFirestore(token: string, user: VerifiedUser): Promise<boolean> {
  if (user.isOwner) return true;
  if (!user.emailVerified) return false;
  try {
    const url = `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/${firebaseConfig.firestoreDatabaseId}/documents/teachers/${encodeURIComponent(user.uid)}`;
    const resp = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) return false;
    const data = (await resp.json()) as { fields?: { active?: { booleanValue?: boolean } } };
    return Boolean(data.fields?.active?.booleanValue);
  } catch {
    return false;
  }
}

async function verifyDiplomaAccessViaFirestore(token: string, user: VerifiedUser): Promise<boolean> {
  if (user.isOwner) return true;
  if (!user.emailVerified) return false;
  try {
    const url = `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/${firebaseConfig.firestoreDatabaseId}/documents/diplomaMembers/${encodeURIComponent(user.uid)}`;
    const resp = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) return false;
    const data = (await resp.json()) as { fields?: { active?: { booleanValue?: boolean } } };
    return Boolean(data.fields?.active?.booleanValue);
  } catch {
    return false;
  }
}

function sealData(payload: unknown): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', SEAL_KEY, iv);
  const plaintext = JSON.stringify(payload);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function unsealData<T>(sealed: string): T {
  const raw = Buffer.from(sealed, 'base64');
  const iv = raw.subarray(0, 12);
  const authTag = raw.subarray(12, 28);
  const ciphertext = raw.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', SEAL_KEY, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  return JSON.parse(decrypted) as T;
}

function signReceipt(payload: Record<string, unknown>): string {
  const data = JSON.stringify(payload);
  const sig = crypto.createHmac('sha256', SEAL_KEY).update(data).digest('hex');
  return Buffer.from(JSON.stringify({ payload, sig })).toString('base64');
}

function verifyReceiptSignature(receiptB64: string): { valid: boolean; payload?: Record<string, unknown> } {
  try {
    const parsed = JSON.parse(Buffer.from(receiptB64, 'base64').toString('utf8')) as {
      payload: Record<string, unknown>;
      sig: string;
    };
    const expected = crypto.createHmac('sha256', SEAL_KEY).update(JSON.stringify(parsed.payload)).digest('hex');
    const valid = crypto.timingSafeEqual(Buffer.from(parsed.sig, 'hex'), Buffer.from(expected, 'hex'));
    return valid ? { valid: true, payload: parsed.payload } : { valid: false };
  } catch {
    return { valid: false };
  }
}

const ALLOWED_EXTENSIONS = new Set(['.pdf', '.docx', '.txt', '.md', '.png', '.jpg', '.jpeg', '.webp']);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      cb(new Error('نوع الملف غير مدعوم أو غير مسموح به أمنياً. الأنواع المسموحة: PDF, DOCX, TXT, PNG, JPG, WEBP.'));
      return;
    }
    cb(null, true);
  },
});

const OBJECTIVE_TYPES = new Set([
  'اختر الإجابة الصحيحة',
  'صح وخطأ',
  'أكمل',
  'التوصيل',
  'الترتيب',
]);

function normalizeArabicText(value: string): string {
  return String(value || '')
    .trim()
    .replace(/[\u064B-\u065F\u0670]/g, '')
    .replace(/[أإآ]/g, 'ا')
    .replace(/ة/g, 'ه')
    .replace(/ى/g, 'ي')
    .replace(/\s+/g, ' ')
    .toLowerCase();
}

interface GeneratedQuestionItem {
  id: string;
  type: string;
  prompt: string;
  options: string[];
  correctAnswer: string;
  explanation: string;
  points: number;
  difficulty: 'easy' | 'medium' | 'hard';
  skill?: string;
  unit?: string;
  lesson?: string;
}

interface SealedAnswerEntry {
  id: string;
  type: string;
  correctAnswer: string;
  points: number;
  explanation?: string;
  skill?: string;
  lesson?: string;
  unit?: string;
  prompt?: string;
  difficulty?: 'easy' | 'medium' | 'hard';
}

async function generateStructuredQuestions(params: {
  stage: string;
  grade: string;
  system: string;
  subject: string;
  unit?: string;
  lesson?: string;
  sourceText: string;
  questionCount: number;
  questionTypes: string[];
  totalMarks: number;
  strictSourceOnly?: boolean;
  difficultyMix?: { easy: number; medium: number; hard: number };
  targetSkills?: string[];
  lessonWeights?: Array<{ lesson: string; unit?: string; weightPct: number }>;
  excludePrompts?: string[];
}): Promise<{ questions: GeneratedQuestionItem[]; totalTokensUsed: number }> {
  const ai = getGeminiClient();
  const count = Math.min(200, Math.max(1, Number(params.questionCount) || 10));
  const typesList =
    Array.isArray(params.questionTypes) && params.questionTypes.length > 0
      ? params.questionTypes
      : ['اختر الإجابة الصحيحة', 'صح وخطأ', 'بم تفسر؟'];

  const allQuestions: GeneratedQuestionItem[] = [];
  const seenPrompts = new Set<string>(
    (params.excludePrompts || []).map((p) => normalizeArabicText(p)).filter(Boolean)
  );
  const batchSize = 25;
  const batches = Math.ceil(count / batchSize);
  let totalTokensUsed = 0;
  const trimmedContext = String(params.sourceText || '').trim().slice(0, 65000);

  const mixText = params.difficultyMix
    ? `توزيع الصعوبة المطلوب تقريباً: سهل ${params.difficultyMix.easy}%، متوسط ${params.difficultyMix.medium}%، صعب ${params.difficultyMix.hard}%.`
    : 'نوّع بين مستويات الصعوبة (easy / medium / hard).';

  const skillsText =
    params.targetSkills && params.targetSkills.length > 0
      ? `المهارات المعرفية المستهدفة (وزّعها في حقل skill): ${params.targetSkills.join('، ')}.`
      : 'حدد المهارة المعرفية المناسبة لكل سؤال في حقل skill (مثل: الفهم والاستيعاب، الاستنتاج والتحليل، التذكر والحفظ، التطبيق النحوي واللغوي، التفسير والسببية).';

  const weightsText =
    params.lessonWeights && params.lessonWeights.length > 0
      ? `أوزان الدروس في هذا الامتحان:\n${params.lessonWeights
          .map((w) => `- ${w.unit ? `${w.unit} / ` : ''}${w.lesson}: ${w.weightPct}%`)
          .join('\n')}`
      : '';

  for (let b = 0; b < batches; b++) {
    const remaining = count - allQuestions.length;
    if (remaining <= 0) break;
    const currentBatchCount = Math.min(batchSize, remaining);
    const existingSnippet =
      allQuestions.length > 0
        ? `\nتجنب تكرار هذه الأسئلة:\n${allQuestions
            .slice(-20)
            .map((q) => `- ${q.prompt}`)
            .join('\n')}`
        : '';

    const prompt = `أنت خبير تربوي متخصص في وضع امتحانات المنهج المصري والأزهري للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜.
البيانات التعليمية:
- المرحلة: ${params.stage || 'عام'}
- الصف: ${params.grade}
- النظام التعليمي: ${params.system || 'التربية والتعليم'}
- المادة: ${params.subject}
${params.unit ? `- الوحدة: ${params.unit}` : ''}
${params.lesson ? `- الدرس: ${params.lesson}` : ''}
- عدد الأسئلة المطلوب في هذه الدفعة: ${currentBatchCount} سؤالاً بالضبط.
- أنواع الأسئلة المسموحة فقط: ${typesList.join('، ')}.
- ${mixText}
- ${skillsText}
${weightsText}
- السياسة المعرفية: ${
      params.strictSourceOnly
        ? 'التزم التزاماً صارماً بالمحتوى المرفق أدناه ولا تخرج عنه أبداً.'
        : 'اعتمد على المحتوى المرفق كمرجع أساسي مع السماح بأسئلة من نفس المنهج المصري للصف المحدد.'
    }

تعليمات الصياغة:
1. لغة عربية فصحى سليمة واضحة ومناسبة لعمر الطالب والصف الدراسي.
2. لكل سؤال من نوع "اختر الإجابة الصحيحة": ضع 4 اختيارات واضحة في options، واكتب النص الدقيق للإجابة الصحيحة داخل correctAnswer بحيث يطابق أحد الاختيارات الأربعة تماماً.
3. لكل سؤال من نوع "صح وخطأ": ضع ["صح", "خطأ"] في options، واكتب "صح" أو "خطأ" في correctAnswer.
4. لباقي الأنواع (أكمل، بم تفسر؟، ما النتائج المترتبة على؟، قارن، ما المقصود؟، أسئلة مقالية، التوصيل، الترتيب، أسئلة شفهية، أنشطة وتطبيقات): اترك options مصفوفة فارغة []، واكتب نموذج الإجابة الدقيق في correctAnswer.
5. حدد اسم الدرس الدقيق لكل سؤال في حقل lesson واسم المهارة في حقل skill.
6. لا تكرر أي سؤال.
${existingSnippet}

المحتوى المصدر من المكتبة:
"""
${trimmedContext || `منهج ${params.subject} - ${params.grade} ${params.unit || ''} ${params.lesson || ''}`}
"""`;

    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: prompt,
      config: {
        thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              type: { type: Type.STRING, description: 'نوع السؤال من القائمة المطلوبة' },
              prompt: { type: Type.STRING, description: 'نص السؤال واضحاً باللغة العربية' },
              options: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: 'الاختيارات لأسئلة الاختيار أو صح وخطأ، وفارغة للمقالي',
              },
              correctAnswer: { type: Type.STRING, description: 'الإجابة الصحيحة النموذجية' },
              explanation: { type: Type.STRING, description: 'توضيح تربوي موجز للإجابة' },
              difficulty: { type: Type.STRING, description: 'easy or medium or hard' },
              skill: { type: Type.STRING, description: 'المهارة المعرفية المقاسة' },
              lesson: { type: Type.STRING, description: 'اسم الدرس التابع له السؤال' },
              unit: { type: Type.STRING, description: 'اسم الوحدة التابع لها السؤال' },
            },
            required: ['type', 'prompt', 'options', 'correctAnswer', 'explanation', 'difficulty', 'skill'],
          },
        },
      },
    });

    totalTokensUsed += response.usageMetadata?.totalTokenCount || 0;
    const parsed = JSON.parse((response.text || '[]').trim()) as Array<{
      type: string;
      prompt: string;
      options: string[];
      correctAnswer: string;
      explanation: string;
      difficulty: string;
      skill?: string;
      lesson?: string;
      unit?: string;
    }>;

    for (const item of parsed) {
      const norm = normalizeArabicText(item.prompt);
      if (!norm || seenPrompts.has(norm)) continue;
      seenPrompts.add(norm);
      allQuestions.push({
        id: `q_${Date.now()}_${allQuestions.length + 1}_${Math.random().toString(36).slice(2, 6)}`,
        type: item.type,
        prompt: item.prompt.trim(),
        options: Array.isArray(item.options) ? item.options : [],
        correctAnswer: (item.correctAnswer || '').trim(),
        explanation: (item.explanation || '').trim(),
        points: 1,
        difficulty: item.difficulty === 'easy' || item.difficulty === 'hard' ? item.difficulty : 'medium',
        skill: (item.skill || params.targetSkills?.[0] || 'الفهم والاستيعاب').trim(),
        lesson: (item.lesson || params.lesson || '').trim(),
        unit: (item.unit || params.unit || '').trim(),
      });
      if (allQuestions.length >= count) break;
    }
  }

  const totalM = Math.max(allQuestions.length, Number(params.totalMarks) || allQuestions.length);
  if (allQuestions.length > 0) {
    const base = Math.floor((totalM / allQuestions.length) * 2) / 2;
    let distributed = 0;
    for (let i = 0; i < allQuestions.length; i++) {
      if (i === allQuestions.length - 1) {
        allQuestions[i].points = Math.max(0.5, Number((totalM - distributed).toFixed(1)));
      } else {
        allQuestions[i].points = Math.max(0.5, base);
        distributed += allQuestions[i].points;
      }
    }
  }

  return { questions: allQuestions, totalTokensUsed };
}

async function startServer() {
  const app = express();
  app.use(cookieParser());
  app.use(express.json({ limit: '12mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      serverTimeMs: Date.now(),
      aiConfigured: Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY'),
    });
  });

  // Extract text (and OCR fallback via Gemini if scanned/image) from uploaded PDF/DOCX/Image
  app.post(
    '/api/library/extract',
    verifyFirebaseBearer,
    (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      upload.single('file')(req, res, (err) => {
        if (err) {
          res.status(400).json({ error: err.message || 'فشل رفع الملف.' });
          return;
        }
        next();
      });
    },
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const token = req.headers.authorization!.slice(7).trim();
        const isAllowedTeacher =
          (await verifyTeacherViaFirestore(token, req.authUser!)) ||
          (await verifyDiplomaAccessViaFirestore(token, req.authUser!));
        if (!isAllowedTeacher) {
          res.status(403).json({ error: 'هذه الصلاحية مخصصة للمدرس أو أعضاء الدبلومة المصرّح لهم فقط.' });
          return;
        }
        const file = req.file;
        if (!file) {
          res.status(400).json({ error: 'لم يتم إرفاق أي ملف.' });
          return;
        }

        const ext = path.extname(file.originalname).toLowerCase();
        let extractedText = '';
        let extractionMethod = 'direct';

        if (ext === '.txt' || ext === '.md') {
          extractedText = file.buffer.toString('utf8').trim();
        } else if (ext === '.docx') {
          const result = await mammoth.extractRawText({ buffer: file.buffer });
          extractedText = (result.value || '').trim();
        } else if (ext === '.pdf') {
          const parser = new PDFParse({ data: file.buffer });
          try {
            const pdfData = await parser.getText();
            extractedText = (pdfData.text || '').trim();
          } finally {
            await parser.destroy();
          }
          if (extractedText.replace(/\s+/g, '').length < 30) {
            try {
              const ai = getGeminiClient();
              const ocrResp = await ai.models.generateContent({
                model: 'gemini-4-hydrogen',
                contents: {
                  parts: [
                    {
                      inlineData: {
                        mimeType: 'application/pdf',
                        data: file.buffer.toString('base64'),
                      },
                    },
                    {
                      text: 'استخرج النص العربي الموجود في هذا المستند بدقة تامة دون تلخيص أو إضافة، وحافظ على العناوين والفقرات والأسئلة.',
                    },
                  ],
                },
                config: { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } },
              });
              const ocrText = (ocrResp.text || '').trim();
              if (ocrText.length > 0) {
                extractedText = ocrText;
                extractionMethod = 'ocr';
              }
            } catch (ocrErr) {
              console.warn('PDF OCR fallback failed:', ocrErr);
              res.json({
                extractedText: '',
                extractionMethod: 'failed',
                warning:
                  'الملف يبدو ممسوحاً ضوئياً (صور) وتعذر استخراج النص تلقائياً. يرجى التأكد من تفعيل مفتاح الذكاء الاصطناعي أو لصق النص يدوياً.',
                fileName: file.originalname,
                fileMime: file.mimetype,
              });
              return;
            }
          }
        } else if (['.png', '.jpg', '.jpeg', '.webp'].includes(ext)) {
          try {
            const ai = getGeminiClient();
            const ocrResp = await ai.models.generateContent({
              model: 'gemini-4-hydrogen',
              contents: {
                parts: [
                  {
                    inlineData: {
                      mimeType: file.mimetype || 'image/jpeg',
                      data: file.buffer.toString('base64'),
                    },
                  },
                  {
                    text: 'استخرج كل النص العربي المكتوب في هذه الصورة بدقة تامة وحافظ على التنسيق والأسئلة كما هي.',
                  },
                ],
              },
              config: { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } },
            });
            extractedText = (ocrResp.text || '').trim();
            extractionMethod = 'ocr';
          } catch (ocrErr) {
            console.warn('Image OCR failed:', ocrErr);
            res.status(422).json({
              error:
                'تعذر استخراج النص من الصورة عبر OCR. يرجى التأكد من إعداد مفتاح Gemini API أو إدخال النص يدوياً.',
            });
            return;
          }
        }

        if (!extractedText) {
          res.json({
            extractedText: '',
            extractionMethod: 'empty',
            warning: 'لم يتم العثور على نص قابل للاستخراج داخل الملف. يمكنك كتابة النص أو لصقه يدوياً.',
            fileName: file.originalname,
            fileMime: file.mimetype,
          });
          return;
        }

        res.json({
          extractedText: extractedText.slice(0, 240000),
          extractionMethod,
          fileName: file.originalname,
          fileMime: file.mimetype,
        });
      } catch (err) {
        console.error('Library extract error:', err);
        res.status(500).json({ error: 'حدث خطأ أثناء معالجة الملف واستخراج النص.' });
      }
    }
  );

  // AI Exam Generation Endpoint (supports lesson weights, difficulty mix, and cognitive skills)
  app.post('/api/ai/generate-exam', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'إنشاء الامتحانات بالذكاء الاصطناعي مخصص للمدرس فقط.' });
        return;
      }

      const body = req.body as {
        stage: string;
        grade: string;
        system: string;
        subject: string;
        unit?: string;
        lesson?: string;
        sourceText: string;
        questionCount: number;
        questionTypes: string[];
        totalMarks: number;
        strictSourceOnly?: boolean;
        difficultyMix?: { easy: number; medium: number; hard: number };
        targetSkills?: string[];
        lessonWeights?: Array<{ lesson: string; unit?: string; weightPct: number }>;
        excludePrompts?: string[];
      };

      const cleanSource = String(body.sourceText || '').trim();
      if (cleanSource.length < 30 && body.strictSourceOnly !== false) {
        res.status(400).json({ error: 'يرجى اختيار مصدر من المكتبة التعليمية يحتوي على نص كافٍ لتوليد الأسئلة منه.' });
        return;
      }

      const result = await generateStructuredQuestions(body);
      res.json({
        questions: result.questions,
        totalTokensUsed: result.totalTokensUsed,
        model: 'gemini-4-hydrogen',
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('AI exam generation error:', err);
      if (msg === 'GEMINI_API_KEY_MISSING') {
        res.status(503).json({
          error:
            'مفتاح Gemini API غير مضاف بعد في لوحة الأسرار (Settings > Secrets). يرجى إضافته لتفعيل التوليد التلقائي بالذكاء الاصطناعي.',
        });
        return;
      }
      res.status(500).json({ error: `تعذر إنشاء الامتحان بالذكاء الاصطناعي: ${msg}` });
    }
  });

  // Action-Executing AI Teacher Assistant (Gemini Function Calling against real platform data)
  app.post('/api/ai/teacher-assistant', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'المساعد الذكي مخصص للمدرس فقط.' });
        return;
      }

      const { prompt, context } = req.body as {
        prompt: string;
        context: {
          librarySummary: Array<{ id: string; title: string; subject: string; grade: string; unit?: string; lesson?: string; snippet: string }>;
          unusedQuestionIds: string[];
          unusedBankCount: number;
          totalBankCount: number;
          weakStudents: Array<{ id: string; name: string; grade: string; avgPct: number; weakLessons: string[]; weakSkills: string[] }>;
          recentExams: Array<{ id: string; title: string; subject: string; grade: string; avgPct: number; attemptCount: number; missedPrompts: string[] }>;
          groups: Array<{ id: string; name: string; grade: string; subject: string }>;
        };
      };

      if (!prompt || !prompt.trim()) {
        res.status(400).json({ error: 'يرجى كتابة الطلب للمساعد الذكي.' });
        return;
      }

      const ai = getGeminiClient();

      const functionDeclarations: FunctionDeclaration[] = [
        {
          name: 'create_exam_from_curriculum',
          description: 'توليد مسودة امتحان جديدة من درس أو وحدة أو محتوى المكتبة التعليمية المتاح.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING, description: 'عنوان الامتحان المقترح' },
              subject: { type: Type.STRING, description: 'اسم المادة (اللغة العربية / الدراسات الاجتماعية / التاريخ / التربوي)' },
              grade: { type: Type.STRING, description: 'الصف الدراسي' },
              unit: { type: Type.STRING, description: 'اسم الوحدة المستهدفة إن وجدت' },
              lesson: { type: Type.STRING, description: 'اسم الدرس المستهدف إن وجد' },
              questionCount: { type: Type.NUMBER, description: 'عدد الأسئلة المطلوب' },
              libraryIds: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: 'معرفات مصادر المكتبة الملائمة من السياق',
              },
            },
            required: ['title', 'subject', 'grade', 'questionCount'],
          },
        },
        {
          name: 'prepare_weakness_review',
          description: 'تجهيز مراجعة أو ورقة تدريبية علاجية للطلاب المتعثرين بناءً على الدروس والمهارات الأضعف.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING, description: 'عنوان المراجعة العلاجية' },
              subject: { type: Type.STRING },
              grade: { type: Type.STRING },
              weakLessons: { type: Type.ARRAY, items: { type: Type.STRING } },
              weakSkills: { type: Type.ARRAY, items: { type: Type.STRING } },
              targetStudentIds: { type: Type.ARRAY, items: { type: Type.STRING } },
              questionCount: { type: Type.NUMBER },
            },
            required: ['title', 'subject', 'grade', 'questionCount'],
          },
        },
        {
          name: 'extract_questions_from_lesson',
          description: 'استخراج بنك أسئلة متنوع من مصدر محدد في المكتبة التعليمية.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              libraryId: { type: Type.STRING, description: 'معرف المصدر في المكتبة' },
              lessonTitle: { type: Type.STRING },
              subject: { type: Type.STRING },
              grade: { type: Type.STRING },
              questionCount: { type: Type.NUMBER },
            },
            required: ['lessonTitle', 'subject', 'grade', 'questionCount'],
          },
        },
        {
          name: 'create_exam_from_unused_questions',
          description: 'تكوين امتحان فوري من الأسئلة التي لم تُستخدم سابقاً في بنك الأسئلة.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING },
              subject: { type: Type.STRING },
              grade: { type: Type.STRING },
              questionCount: { type: Type.NUMBER },
            },
            required: ['title', 'questionCount'],
          },
        },
        {
          name: 'analyze_group_exam_performance',
          description: 'تحليل نتائج امتحان معين أو أداء مجموعة وتقديم توصيات تعليمية فورية.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              examId: { type: Type.STRING, description: 'معرف الامتحان إن وجد في السياق' },
              focusArea: { type: Type.STRING, description: 'مجال التركيز المطلوب تحليله' },
            },
            required: ['focusArea'],
          },
        },
        {
          name: 'create_remedial_homework_from_errors',
          description: 'إنشاء واجب منزلي علاجي يستهدف الأسئلة التي أخطأ فيها الطلاب.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING },
              subject: { type: Type.STRING },
              grade: { type: Type.STRING },
              missedTopics: { type: Type.ARRAY, items: { type: Type.STRING } },
              questionCount: { type: Type.NUMBER },
            },
            required: ['title', 'subject', 'grade', 'questionCount'],
          },
        },
      ];

      const systemContextPrompt = `أنت المساعد التنفيذي الذكي للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜 داخل منصته التعليمية.
مهمتك تنفيذ طلبات المعلم العملية عبر استدعاء الأدوات (Function Calls) المتاحة بناءً على بيانات المنصة الحقيقية التالية:

1. مصادر المكتبة المتاحة (${context.librarySummary.length}):
${context.librarySummary
  .slice(0, 20)
  .map((l) => `- [${l.id}] ${l.title} (${l.subject} | ${l.grade} | وحدة: ${l.unit || '-'} | درس: ${l.lesson || '-'})`)
  .join('\n')}

2. بنك الأسئلة: الإجمالي ${context.totalBankCount} سؤالاً، منها ${context.unusedBankCount} سؤالاً لم يُستخدم بعد.

3. الطلاب الذين يحتاجون متابعة أو تراجعاً (${context.weakStudents.length}):
${context.weakStudents
  .slice(0, 12)
  .map((s) => `- [${s.id}] ${s.name} (${s.grade}): متوسط ${s.avgPct}% | دروس ضعيفة: ${s.weakLessons.join('، ') || 'عام'}`)
  .join('\n')}

4. أحدث الامتحانات ونتائجها (${context.recentExams.length}):
${context.recentExams
  .slice(0, 10)
  .map((e) => `- [${e.id}] ${e.title} (${e.subject} | ${e.grade}): متوسط ${e.avgPct}% من ${e.attemptCount} تسليم`)
  .join('\n')}

اختر الأداة المناسبة ونفذ الطلب بدقة. إذا طُلب تحليل فقط فاستدعِ أداة التحليل ثم اشرح النتائج بوضوح بالعربية.`;

      const firstResp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `${systemContextPrompt}\n\nطلب الأستاذ الآن:\n"${prompt.trim()}"`,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          tools: [{ functionDeclarations }],
        },
      });

      const calls = firstResp.functionCalls || [];
      let actionType = 'advice';
      let actionPayload: Record<string, unknown> = {};
      let assistantReply = (firstResp.text || '').trim();

      if (calls.length > 0) {
        const call = calls[0];
        const args = (call.args || {}) as Record<string, unknown>;

        if (call.name === 'create_exam_from_curriculum' || call.name === 'extract_questions_from_lesson') {
          const libIds = Array.isArray(args.libraryIds)
            ? (args.libraryIds as string[])
            : typeof args.libraryId === 'string'
            ? [args.libraryId]
            : [];
          const matchedSources = context.librarySummary.filter(
            (l) =>
              libIds.includes(l.id) ||
              (typeof args.lesson === 'string' && l.lesson?.includes(args.lesson)) ||
              (typeof args.unit === 'string' && l.unit?.includes(args.unit)) ||
              (typeof args.subject === 'string' && l.subject === args.subject && l.grade === args.grade)
          );
          const sourceText = matchedSources.map((m) => `【${m.title}】\n${m.snippet}`).join('\n\n');
          const count = Math.min(30, Math.max(4, Number(args.questionCount) || 10));
          const gen = await generateStructuredQuestions({
            stage: 'عام',
            grade: String(args.grade || matchedSources[0]?.grade || 'الصف الأول الإعدادي'),
            system: 'التربية والتعليم',
            subject: String(args.subject || matchedSources[0]?.subject || 'اللغة العربية'),
            unit: String(args.unit || ''),
            lesson: String(args.lesson || args.lessonTitle || ''),
            sourceText: sourceText || `موضوع: ${String(args.title || args.lessonTitle || prompt)}`,
            questionCount: count,
            questionTypes: ['اختر الإجابة الصحيحة', 'صح وخطأ', 'أكمل', 'بم تفسر؟'],
            totalMarks: count * 2,
            strictSourceOnly: false,
          });
          actionType = 'draft_exam';
          actionPayload = {
            title: String(args.title || `امتحان ${args.lessonTitle || args.subject}`),
            subject: String(args.subject || matchedSources[0]?.subject || 'اللغة العربية'),
            grade: String(args.grade || matchedSources[0]?.grade || 'الصف الأول الإعدادي'),
            unit: String(args.unit || ''),
            lesson: String(args.lesson || args.lessonTitle || ''),
            questions: gen.questions,
            purpose: 'exam',
          };
          if (!assistantReply) {
            assistantReply = `تم تجهيز ${gen.questions.length} سؤالاً بعنوان "${actionPayload.title}" بناءً على المنهج والمصادر المتاحة. يمكنك اعتمادها مباشرة في مصنع الامتحانات أو حفظها في بنك الأسئلة.`;
          }
        } else if (call.name === 'prepare_weakness_review' || call.name === 'create_remedial_homework_from_errors') {
          const weakLessons = Array.isArray(args.weakLessons)
            ? (args.weakLessons as string[])
            : Array.isArray(args.missedTopics)
            ? (args.missedTopics as string[])
            : context.weakStudents.flatMap((w) => w.weakLessons).slice(0, 4);
          const weakSkills = Array.isArray(args.weakSkills)
            ? (args.weakSkills as string[])
            : context.weakStudents.flatMap((w) => w.weakSkills).slice(0, 4);
          const count = Math.min(20, Math.max(5, Number(args.questionCount) || 8));
          const targetStudentIds = Array.isArray(args.targetStudentIds)
            ? (args.targetStudentIds as string[])
            : context.weakStudents.map((s) => s.id);
          const subject = String(args.subject || 'اللغة العربية');
          const grade = String(args.grade || context.weakStudents[0]?.grade || 'الصف الأول الإعدادي');
          const relatedSnippets = context.librarySummary
            .filter((l) => l.subject === subject || weakLessons.some((wl) => l.title.includes(wl) || l.lesson?.includes(wl)))
            .map((l) => l.snippet)
            .join('\n\n');

          const gen = await generateStructuredQuestions({
            stage: 'عام',
            grade,
            system: 'التربية والتعليم',
            subject,
            lesson: weakLessons.join('، '),
            sourceText:
              relatedSnippets ||
              `موضوعات تحتاج تقوية وعلاج: ${weakLessons.join('، ')}. المهارات: ${weakSkills.join('، ')}`,
            questionCount: count,
            questionTypes: ['اختر الإجابة الصحيحة', 'صح وخطأ', 'أكمل'],
            totalMarks: count * 2,
            strictSourceOnly: false,
            difficultyMix: { easy: 40, medium: 40, hard: 20 },
            targetSkills: weakSkills,
          });
          actionType = 'remedial_draft';
          actionPayload = {
            title: String(args.title || 'مراجعة وواجب علاجي مستهدف'),
            subject,
            grade,
            weakLessons,
            weakSkills,
            targetStudentIds,
            questions: gen.questions,
            purpose: call.name === 'create_remedial_homework_from_errors' ? 'homework' : 'remedial',
          };
          if (!assistantReply) {
            assistantReply = `تم إعداد ${count} أسئلة علاجية مخصصة تستهدف نقاط الضعف (${weakLessons.join('، ') || 'المهارات الأساسية'}) لعدد ${targetStudentIds.length} طالب. يمكنك إرسالها كواجب علاجي فوري أو فتحها في مصنع الامتحانات.`;
          }
        } else if (call.name === 'create_exam_from_unused_questions') {
          const count = Math.min(50, Math.max(1, Number(args.questionCount) || 10));
          const pickedIds = context.unusedQuestionIds.slice(0, count);
          actionType = 'pick_unused_bank';
          actionPayload = {
            title: String(args.title || 'امتحان من الأسئلة غير المستخدمة'),
            subject: String(args.subject || ''),
            grade: String(args.grade || ''),
            questionCount: count,
            questionIds: pickedIds,
          };
          assistantReply =
            pickedIds.length > 0
              ? `تم اختيار ${pickedIds.length} سؤالاً لم تُستخدم سابقاً من بنك الأسئلة لتكوين "${actionPayload.title}". اضغط "فتح في مصنع الامتحانات" لاعتمادها.`
              : 'جميع أسئلة البنك الحالي قد تم استخدامها من قبل، يمكنك استبدال ذلك بتوليد أسئلة جديدة من المكتبة.';
        } else if (call.name === 'analyze_group_exam_performance') {
          const targetExam =
            context.recentExams.find((e) => e.id === args.examId) || context.recentExams[0];
          const summaryPrompt = `حلل أداء المجموعة والامتحان التالي وقدّم تقريراً تربوياً مركزاً في 4 نقاط عملية للأستاذ:
الامتحان: ${targetExam?.title || 'أحدث النتائج'}
المتوسط: ${targetExam?.avgPct ?? 0}% من ${targetExam?.attemptCount ?? 0} تسليم
الأسئلة الأكثر إخفاقاً: ${targetExam?.missedPrompts.join(' | ') || 'لا توجد أخطاء مسجلة بعد'}
الطلاب المتراجعون: ${context.weakStudents.map((w) => `${w.name} (${w.avgPct}%)`).join('، ') || 'لا يوجد'}
طلب المعلم: ${prompt}`;
          const analysisResp = await ai.models.generateContent({
            model: 'gemini-4-hydrogen',
            contents: summaryPrompt,
            config: { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } },
          });
          actionType = 'analysis_report';
          actionPayload = {
            examId: targetExam?.id || '',
            focusArea: String(args.focusArea || ''),
            missedPrompts: targetExam?.missedPrompts || [],
            weakStudents: context.weakStudents,
          };
          assistantReply = (analysisResp.text || '').trim();
        }
      }

      if (!assistantReply) {
        assistantReply = 'تم تحليل طلبك. يمكنك تخصيص الطلب باسم الدرس أو المجموعة وسأنفذه فوراً.';
      }

      res.json({
        reply: assistantReply,
        actionType,
        actionPayload,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('AI Teacher Assistant error:', err);
      if (msg === 'GEMINI_API_KEY_MISSING') {
        res.status(503).json({
          error: 'مفتاح Gemini API غير مضاف بعد في لوحة الأسرار لتشغيل المساعد الذكي.',
        });
        return;
      }
      res.status(500).json({ error: `تعذر تنفيذ طلب المساعد الذكي: ${msg}` });
    }
  });

  // AI-Assisted Essay Grading Suggestion (Teacher-only review helper)
  app.post('/api/ai/grade-essay-assist', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'التصحيح بالذكاء الاصطناعي مخصص للمدرس فقط.' });
        return;
      }

      const { examId, studentAnswers, questions } = req.body as {
        examId: string;
        studentAnswers: Record<string, string>;
        questions: Array<{ id: string; type: string; prompt: string; correctAnswer: string; points: number }>;
      };

      if (!examId || !Array.isArray(questions) || questions.length === 0) {
        res.status(400).json({ error: 'لا توجد أسئلة مقالية لتقييمها.' });
        return;
      }

      const ai = getGeminiClient();
      const essayItems = questions.map((q) => ({
        id: q.id,
        prompt: q.prompt,
        modelAnswer: q.correctAnswer,
        maxPoints: Number(q.points) || 1,
        studentAnswer: (studentAnswers[q.id] || '').trim() || '(لم يجب الطالب)',
      }));

      const resp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `أنت مساعد تصحيح تربوي للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜. قيّم إجابات الطالب المقالية مقارنة بنموذج الإجابة واقترح درجة عادلة وملاحظة تربوية مختصرة لكل سؤال:\n${JSON.stringify(
          essayItems,
          null,
          2
        )}`,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                questionId: { type: Type.STRING },
                suggestedScore: { type: Type.NUMBER },
                feedback: { type: Type.STRING },
              },
              required: ['questionId', 'suggestedScore', 'feedback'],
            },
          },
        },
      });

      const parsed = JSON.parse((resp.text || '[]').trim()) as Array<{
        questionId: string;
        suggestedScore: number;
        feedback: string;
      }>;

      const feedbackMap: Record<string, { suggestedScore: number; maxPoints: number; feedback: string }> = {};
      let totalSuggestedEssay = 0;

      for (const item of essayItems) {
        const match = parsed.find((p) => p.questionId === item.id);
        const bounded = match
          ? Math.max(0, Math.min(item.maxPoints, Number(match.suggestedScore) || 0))
          : 0;
        totalSuggestedEssay += bounded;
        feedbackMap[item.id] = {
          suggestedScore: Number(bounded.toFixed(1)),
          maxPoints: item.maxPoints,
          feedback: match?.feedback || 'يرجى المراجعة اليدوية.',
        };
      }

      res.json({
        feedbackMap,
        totalSuggestedEssay: Number(totalSuggestedEssay.toFixed(2)),
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر التقييم الآلي للمقالي: ${msg}` });
    }
  });

  // Smart Welcome Assistant Optional Server-Side Gemini Narrative Summary
  app.post('/api/ai/welcome-summary', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'هذه الخدمة مخصصة للمدرس أو المساعد الإداري فقط.' });
        return;
      }

      const { greeting, teacherName, stats, latestActivity } = req.body as {
        greeting: string;
        teacherName: string;
        stats: {
          todaySlots: number;
          expectedStudents: number;
          newStudents: number;
          pendingJoins: number;
          pendingHomeworks: number;
          pendingGrading: number;
          examsAwaitingApproval: number;
          importantAlerts: number;
          overdueTasks: number;
          totalActiveStudents: number;
        };
        latestActivity?: string;
      };

      const ai = getGeminiClient();
      const prompt = `أنت مساعد الترحيب الذكي للأستاذ ${teacherName || '𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜'} داخل لوحة القيادة التعليمية.
اكتب ملخصاً عربياً فصيحاً قصيراً وواضحاً (جملتين إلى ثلاث جمل بحد أقصى، بدون نقاط أو تنسيق معقد) يلخص حالة العمل اليومية استناداً حصرياً إلى الأرقام الحقيقية التالية دون اختراع أو إضافة أي رقم غير مذكور:
- التحية الحالية: ${greeting}
- الحصص المجدولة اليوم: ${Number(stats?.todaySlots) || 0} (لـ ${Number(stats?.expectedStudents) || 0} طالب)
- الطلاب الجدد وطلبات الانضمام: ${Number(stats?.newStudents) || 0} طلاب جدد و${Number(stats?.pendingJoins) || 0} طلبات انضمام
- الواجبات المطلوب متابعتها: ${Number(stats?.pendingHomeworks) || 0}
- أعمال التصحيح بانتظار المراجعة: ${Number(stats?.pendingGrading) || 0}
- الامتحانات التي تحتاج اعتماداً أو نشراً: ${Number(stats?.examsAwaitingApproval) || 0}
- التنبيهات المهمة: ${Number(stats?.importantAlerts) || 0}
- المهام المتأخرة: ${Number(stats?.overdueTasks) || 0}
- إجمالي الطلاب النشطين: ${Number(stats?.totalActiveStudents) || 0}
- آخر نشاط مسجل: ${latestActivity || 'لا يوجد نشاط مسجل بعد'}

إذا كانت كل مهام المتابعة والتصحيح والتنبيهات صفراً، أخبر المدرس بوضوح أنه لا توجد مهام معلقة حالياً واقترح عليه خطوة عملية مناسبة.`;

      const resp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: prompt,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
        },
      });

      const summary = (resp.text || '').trim();
      if (!summary) {
        res.status(502).json({ error: 'لم يرجع الخادم نصاً صالحاً للملخص.' });
        return;
      }

      res.json({ summary, model: 'gemini-4-hydrogen' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg === 'GEMINI_API_KEY_MISSING') {
        res.status(503).json({
          error: 'مفتاح Gemini API غير مُعد على الخادم. يتم استخدام الملخص المحلي المعتمد على البيانات.',
        });
        return;
      }
      res.status(500).json({ error: `تعذر توليد الملخص عبر الخادم: ${msg}` });
    }
  });

  // Full Conversational & Analytical Smart Platform Agent (Multi-turn Gemini + Live Platform Snapshot + Tools)
  app.post('/api/ai/smart-agent', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'المساعد الذكي مخصص للمدرس أو المساعد الإداري المصرح له فقط.' });
        return;
      }

      const { message, history, platformSnapshot } = req.body as {
        message: string;
        history?: Array<{ role: 'user' | 'model'; text: string }>;
        platformSnapshot?: Record<string, unknown>;
      };

      const cleanMessage = String(message || '').trim();
      if (!cleanMessage) {
        res.status(400).json({ error: 'يرجى كتابة سؤالك أو طلبك للمساعد الذكي.' });
        return;
      }

      const ai = getGeminiClient();

      const agentTools: FunctionDeclaration[] = [
        {
          name: 'draft_exam_or_worksheet',
          description:
            'توليد امتحان جديد أو ورقة عمل جديدة أو أسئلة تدريبية مولدة من الصفر بأسئلة وإجابات نموذجية عند طلب المدرس تأليف/توليد اختبار جديد.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING, description: 'عنوان الامتحان أو ورقة العمل' },
              kind: { type: Type.STRING, description: 'exam or worksheet or revision' },
              subject: { type: Type.STRING, description: 'المادة الدراسية' },
              grade: { type: Type.STRING, description: 'الصف الدراسي المصري' },
              unit: { type: Type.STRING, description: 'اسم الوحدة إن وُجد' },
              lesson: { type: Type.STRING, description: 'اسم الدرس أو الموضوع' },
              questionCount: { type: Type.NUMBER, description: 'عدد الأسئلة المطلوبة (افتراضي 10)' },
              questionTypes: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: 'أنواع الأسئلة المطلوبة',
              },
            },
            required: ['title', 'subject', 'grade', 'questionCount'],
          },
        },
        {
          name: 'place_exam_in_platform',
          description:
            'استخدام هذه الأداة عندما يلصق الأستاذ امتحاناً كاملاً أو نص أسئلة امتحان ويريد وضعه/حفظه في المكان الصحيح بقسم الامتحانات (مع خيار نشره أو حفظ أسئلته في بنك الأسئلة).',
          parameters: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING, description: 'عنوان الامتحان المستنتج أو المطلوب' },
              subject: { type: Type.STRING, description: 'المادة الدراسية' },
              grade: { type: Type.STRING, description: 'الصف الدراسي المصري مثل الصف الثالث الإعدادي' },
              examCategory: { type: Type.STRING, description: 'تصنيف الامتحان مثل امتحان شهري أو امتحان على درس' },
              unit: { type: Type.STRING, description: 'الوحدة الدراسية إن وجدت' },
              lesson: { type: Type.STRING, description: 'الدرس إن وجد' },
              durationMinutes: { type: Type.NUMBER, description: 'مدة الامتحان بالدقائق (افتراضي 30)' },
              published: { type: Type.BOOLEAN, description: 'هل يتم نشره للطلاب أم حفظه كمسودة؟ (افتراضي false إلا لو طلب النشر)' },
              alsoAddToBank: { type: Type.BOOLEAN, description: 'هل يتم حفظ الأسئلة في بنك الأسئلة أيضاً؟ (افتراضي true)' },
              rawExamText: { type: Type.STRING, description: 'النص الكامل للامتحان والأسئلة التي أرسلها المدرس لاستخراجها بدقة' },
            },
            required: ['title', 'subject', 'grade', 'rawExamText'],
          },
        },
        {
          name: 'add_questions_to_bank',
          description:
            'استخدام هذه الأداة عندما يرسل أو يلصق الأستاذ مجموعة أسئلة (سواء مرقمة أو نص خام) ويريد إضافتها ووضعها في بنك الأسئلة المصنف بالمكان الصحيح.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              subject: { type: Type.STRING, description: 'المادة الدراسية' },
              grade: { type: Type.STRING, description: 'الصف الدراسي' },
              unit: { type: Type.STRING, description: 'الوحدة إن وجدت' },
              lesson: { type: Type.STRING, description: 'الدرس إن وجد' },
              sourceTitle: { type: Type.STRING, description: 'عنوان المصدر أو الدرس' },
              rawQuestionsText: { type: Type.STRING, description: 'النص الكامل للأسئلة المراد تحليلها وإضافتها لبنك الأسئلة' },
            },
            required: ['subject', 'grade', 'rawQuestionsText'],
          },
        },
        {
          name: 'save_content_to_library',
          description:
            'حفظ شرح درس أو مذكرة أو ملخص أو نص أرسله المدرس داخل المكتبة التعليمية في المجلد/القسم والصف والمادة الصحيحة.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING, description: 'عنوان الملف في المكتبة' },
              subject: { type: Type.STRING, description: 'المادة الدراسية' },
              grade: { type: Type.STRING, description: 'الصف الدراسي' },
              unit: { type: Type.STRING, description: 'الوحدة إن وجدت' },
              lesson: { type: Type.STRING, description: 'الدرس إن وجد' },
              contentType: { type: Type.STRING, description: 'شرح أو ملخص أو واجب أو مراجعة أو أسئلة' },
              folder: { type: Type.STRING, description: 'اسم القسم أو المجلد داخل المكتبة (افتراضي: المناهج الأساسية أو ما يحدده المدرس)' },
              extractedText: { type: Type.STRING, description: 'النص الكامل للمحتوى التعليمي المراد حفظه' },
              sharedWithStudents: { type: Type.BOOLEAN, description: 'مشاركة الملف مع بوابة الطلاب أم حفظه للمعلم فقط' },
            },
            required: ['title', 'subject', 'grade', 'extractedText'],
          },
        },
        {
          name: 'add_platform_section_or_band',
          description:
            'إضافة قسم جديد أو مجلد جديد أو مادة جديدة أو تصنيف امتحان جديد أو نظام/مرحلة أو بند مخصص جديد داخل المنصة عندما يطلب المدرس إضافة قسم أو بند جديد في المنصة.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              settingAction: {
                type: Type.STRING,
                description:
                  'أحد القيم: add_subject | add_library_folder | add_exam_category | add_stage | add_system | create_band | add_band_item',
              },
              label: { type: Type.STRING, description: 'اسم القسم أو المادة أو التصنيف أو البند الجديد' },
              value: { type: Type.STRING, description: 'قيمة أو تفاصيل اختيارية للبند' },
              targetArea: { type: Type.STRING, description: 'general | students | exams | library' },
              bandTitle: { type: Type.STRING, description: 'اسم القسم المخصص الأب إذا كان الإجراء add_band_item' },
              description: { type: Type.STRING, description: 'وصف مختصر للقسم أو البند الجديد' },
            },
            required: ['settingAction', 'label'],
          },
        },
        {
          name: 'manage_registration_or_group_or_announcement',
          description:
            'إدارة طلبات تسجيل الطلاب الجدد (قبول/رفض طلب انضمام من pendingJoinRequests)، أو إنشاء مجموعة دراسية جديدة، أو نشر إعلان للطلاب/أولياء الأمور، أو إضافة حصة بالجدول.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              actionType: {
                type: Type.STRING,
                description: 'approve_join_request | reject_join_request | create_group | publish_announcement | add_schedule_slot',
              },
              targetStudentName: { type: Type.STRING, description: 'اسم الطالب في طلب التسجيل أو اتركه فارغاً لقبول جميع الطلبات المعلقة إن طلب المدرس ذلك' },
              groupName: { type: Type.STRING, description: 'اسم المجموعة الجديدة أو المجموعة المستهدفة' },
              grade: { type: Type.STRING, description: 'الصف الدراسي' },
              subject: { type: Type.STRING, description: 'المادة الدراسية' },
              system: { type: Type.STRING, description: 'النظام التعليمي (التربية والتعليم / الأزهر الشريف / ...)' },
              monthlyFee: { type: Type.NUMBER, description: 'قيمة الاشتراك الشهري بالجنيه' },
              scheduleSummary: { type: Type.STRING, description: 'ملخص المواعيد' },
              announcementTitle: { type: Type.STRING, description: 'عنوان الإعلان' },
              announcementBody: { type: Type.STRING, description: 'نص الإعلان' },
              targetType: { type: Type.STRING, description: 'all | group | grade | parents' },
              dayOfWeek: { type: Type.STRING, description: 'السبت | الأحد | الإثنين | الثلاثاء | الأربعاء | الخميس' },
              startTime: { type: Type.STRING, description: 'وقت البداية HH:mm مثل 16:00' },
              endTime: { type: Type.STRING, description: 'وقت النهاية HH:mm مثل 17:30' },
              notes: { type: Type.STRING, description: 'ملاحظات إضافية' },
            },
            required: ['actionType'],
          },
        },
        {
          name: 'draft_lesson_study_guide',
          description:
            'إنشاء مذكرة شرح منظمة أو ملخص درس كامل أو خطة حصة تعليمية قابلة للحفظ في المكتبة والطباعة Word/PDF عند طلب المدرس تأليف مذكرة أو تلخيص درس.',
          parameters: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING, description: 'عنوان المذكرة أو الملخص' },
              subject: { type: Type.STRING, description: 'المادة الدراسية' },
              grade: { type: Type.STRING, description: 'الصف الدراسي' },
              lesson: { type: Type.STRING, description: 'اسم الدرس' },
              focusPoints: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: 'المحاور الأساسية التي يجب تغطيتها',
              },
            },
            required: ['title', 'subject', 'grade', 'lesson'],
          },
        },
      ];

      const safeSnapshotStr = JSON.stringify(platformSnapshot || {}, null, 0).slice(0, 48000);

      const systemInstruction = `أنت العقل التشغيلي التنفيذي والمساعد الذكي الشامل للأستاذ "𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜" داخل منصته التعليمية والإدارية (المناهج المصرية والأزهرية).

مهمتك الأساسية: أن يكون لديك القدرة الكاملة على تنفيذ أي طلب عملي يطلبه الأستاذ في المنصة مباشرة وليس مجرد الكلام العام:
1. الصدق والدقة المطلقة:
   - التزم حرفياً ببيانات platformSnapshot الحية (الطلاب، الدرجات، الغياب، المدفوعات، الجدول، طلبات التسجيل pendingJoinRequests، الأقسام المخصصة customBands، المجلدات customLibraryFolders). لا تخترع أرقاماً أو أسماء طلاب.
2. وضع الامتحانات والأسئلة والمحتوى في مكانها الصحيح:
   - إذا لصق الأستاذ نص امتحان أو أرسل أسئلة امتحان ليضعها في المنصة -> استدعِ فوراً أداة place_exam_in_platform لتصنيفها ووضعها في قسم الامتحانات وبنك الأسئلة.
   - إذا لصق الأستاذ أسئلة (اختياري/صح وخطأ/أكمل/مقالي) ليحفظها في بنك الأسئلة -> استدعِ فوراً أداة add_questions_to_bank.
   - إذا أرسل الأستاذ شرحاً أو مذكرة أو تلخيصاً ليحفظه في المكتبة -> استدعِ save_content_to_library وحدد القسم/المجلد والصف والمادة بدقة.
   - إذا طلب منك تأليف امتحان جديد من الصفر -> استدعِ draft_exam_or_worksheet.
   - إذا طلب منك تأليف مذكرة أو ملخص -> استدعِ draft_lesson_study_guide.
3. إضافة أقسام ومواد وتصنيفات وبنود جديدة داخل المنصة:
   - إذا طلب الأستاذ إضافة قسم جديد أو مجلد في المكتبة أو مادة جديدة أو تصنيف امتحان جديد أو مرحلة/نظام أو أي بند متابعة جديد في المنصة -> استدعِ فوراً أداة add_platform_section_or_band بالنوع المناسب ولا تقل أبداً "لا أستطيع تعديل المنصة"!
4. إدارة التسجيل والمجموعات والجدول والإعلانات:
   - إذا طلب قبول أو مراجعة طلبات تسجيل الطلاب الجدد (انظر pendingJoinRequests في اللقطة)، أو إنشاء مجموعة جديدة، أو نشر إعلان، أو إضافة حصة بالجدول -> استدعِ أداة manage_registration_or_group_or_announcement.
5. الأسئلة التحليلية والتربوية:
   - أجب مباشرة بتحليل عملي منسق ومفصل باللغة العربية السلسة مع أرقام وأسماء حقيقية من المنصة.
6. الوعي بالصفحة الحالية (activeContext):
   - راعِ القسم المفتوح حالياً أمام المدرس في \`platformSnapshot.activeContext\` (مثل صفحة الطلاب أو الامتحانات أو بنك الأسئلة أو المدفوعات) وقدّم اقتراحات وخطوات عملية مرتبطة به مباشرة عند الحاجة.`;

      const recentHistory = Array.isArray(history)
        ? history
            .filter((h) => h && (h.role === 'user' || h.role === 'model') && typeof h.text === 'string' && h.text.trim())
            .slice(-10)
        : [];

      const contents = [
        ...recentHistory.map((h) => ({
          role: h.role,
          parts: [{ text: h.text.slice(0, 3500) }],
        })),
        {
          role: 'user',
          parts: [
            {
              text: `بيانات المنصة الحية الحالية (JSON):\n${safeSnapshotStr}\n\nطلب / سؤال الأستاذ الآن:\n${cleanMessage}`,
            },
          ],
        },
      ];

      const aiResp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents,
        config: {
          systemInstruction,
          tools: [{ functionDeclarations: agentTools }],
        },
      });

      const parseRawQuestionsViaGemini = async (rawText: string, subject: string, grade: string) => {
        const parseResp = await ai.models.generateContent({
          model: 'gemini-4-hydrogen',
          contents: `حوّل النص التالي الذي أرسله المعلم إلى قائمة أسئلة مهيكلة بدقة دون حذف أي سؤال من النص، مع استنتاج النوع والإجابة النموذجية والشرح إن أمكن:\nالمادة: ${subject}\nالصف: ${grade}\n\nالنص:\n${rawText.slice(0, 28000)}`,
          config: {
            responseMimeType: 'application/json',
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                questions: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      type: {
                        type: Type.STRING,
                        description:
                          'اختر الإجابة الصحيحة | صح وخطأ | أكمل | بم تفسر؟ | ما النتائج المترتبة على؟ | قارن | ما المقصود؟ | أسئلة مقالية',
                      },
                      prompt: { type: Type.STRING },
                      options: { type: Type.ARRAY, items: { type: Type.STRING } },
                      correctAnswer: { type: Type.STRING },
                      explanation: { type: Type.STRING },
                      points: { type: Type.NUMBER },
                      difficulty: { type: Type.STRING, description: 'easy | medium | hard' },
                      lesson: { type: Type.STRING },
                      skill: { type: Type.STRING },
                    },
                    required: ['type', 'prompt', 'correctAnswer'],
                  },
                },
              },
              required: ['questions'],
            },
          },
        });
        const parsed = JSON.parse((parseResp.text || '{}').trim()) as {
          questions?: Array<{
            type?: string;
            prompt?: string;
            options?: string[];
            correctAnswer?: string;
            explanation?: string;
            points?: number;
            difficulty?: string;
            lesson?: string;
            skill?: string;
          }>;
        };
        const rawList = Array.isArray(parsed.questions) ? parsed.questions : [];
        return rawList
          .filter((q) => q && typeof q.prompt === 'string' && q.prompt.trim().length > 1)
          .map((q, idx) => {
            const diff: 'easy' | 'medium' | 'hard' =
              q.difficulty === 'easy' || q.difficulty === 'hard' ? q.difficulty : 'medium';
            return {
              id: `aiq_${Date.now()}_${idx + 1}`,
              type: String(q.type || 'أسئلة مقالية'),
              prompt: String(q.prompt).trim(),
              options: Array.isArray(q.options) ? q.options.map((o) => String(o)) : [],
              correctAnswer: String(q.correctAnswer || 'راجع الإجابة النموذجية').trim(),
              explanation: String(q.explanation || '').trim(),
              points: Number(q.points) > 0 ? Number(q.points) : 2,
              difficulty: diff,
              lesson: q.lesson ? String(q.lesson).trim() : '',
              skill: q.skill ? String(q.skill).trim() : 'الفهم والاستيعاب',
            };
          });
      };

      const inferStageAndSystem = (grade: string) => {
        const stage = grade.includes('الابتدائي')
          ? 'المرحلة الابتدائية'
          : grade.includes('الثانوي')
          ? 'المرحلة الثانوية'
          : 'المرحلة الإعدادية';
        const system = grade.includes('الثانوي') ? 'الثانوية العامة' : 'التربية والتعليم';
        return { stage, system };
      };

      const calls = aiResp.functionCalls || [];
      let replyText = (aiResp.text || '').trim();
      let draftExamArtifact: Record<string, unknown> | undefined;
      let platformCommand: Record<string, unknown> | undefined;
      const suggestedActions: Array<{
        label: string;
        prompt?: string;
        navSection?: string;
        navSubAction?: string;
        copyText?: string;
      }> = [];

      if (calls.length > 0) {
        const call = calls[0];
        const args = (call.args || {}) as Record<string, unknown>;

        if (call.name === 'draft_exam_or_worksheet') {
          const subject = String(args.subject || 'اللغة العربية');
          const grade = String(args.grade || 'الصف الأول الإعدادي');
          const lesson = String(args.lesson || '');
          const unit = String(args.unit || '');
          const count = Math.min(30, Math.max(4, Number(args.questionCount) || 10));
          const kind = args.kind === 'worksheet' || args.kind === 'revision' ? args.kind : 'exam';
          const qTypes =
            Array.isArray(args.questionTypes) && args.questionTypes.length > 0
              ? (args.questionTypes as string[])
              : ['اختر الإجابة الصحيحة', 'صح وخطأ', 'أكمل', 'بم تفسر؟'];

          const libList = Array.isArray((platformSnapshot as { librarySummary?: unknown[] } | undefined)?.librarySummary)
            ? (platformSnapshot as { librarySummary: Array<{ title?: string; subject?: string; grade?: string; lesson?: string; snippet?: string }> }).librarySummary
            : [];
          const matchingLib = libList.filter(
            (l) =>
              (l.subject === subject || !args.subject) &&
              (!lesson || (l.lesson || '').includes(lesson) || (l.title || '').includes(lesson))
          );
          const sourceText =
            matchingLib.map((m) => `【${m.title || ''}】\n${m.snippet || ''}`).join('\n\n') ||
            `المنهج المصري: ${subject} — ${grade}${unit ? ` — ${unit}` : ''}${lesson ? ` — ${lesson}` : ''}\nطلب المعلم: ${cleanMessage}`;

          const { stage, system } = inferStageAndSystem(grade);
          const gen = await generateStructuredQuestions({
            stage,
            grade,
            system,
            subject,
            unit,
            lesson,
            sourceText,
            questionCount: count,
            questionTypes: qTypes,
            totalMarks: count * 2,
            strictSourceOnly: false,
          });

          const title = String(args.title || `${kind === 'worksheet' ? 'ورقة عمل' : 'امتحان'} ${subject} — ${grade}`);
          draftExamArtifact = {
            kind,
            title,
            stage,
            grade,
            system,
            subject,
            unit,
            lesson,
            questionCount: gen.questions.length,
            variantsCount: 1,
            includeAnswerKey: true,
            questions: gen.questions,
            sourceLibraryIds: [],
            reviewNotes: [
              matchingLib.length > 0
                ? `تم الاستناد إلى ${matchingLib.length} مصدر من مكتبتك مع إثراء المنهج عبر Gemini.`
                : 'تم التوليد وفق المنهج المصري المعتمد عبر محرك Gemini.',
            ],
          };

          if (!replyText) {
            replyText = `تم إعداد "${title}" بعدد ${gen.questions.length} سؤالاً متدرج الصعوبة شاملة الإجابات النموذجية.\nراجع المسودة أدناه واضغط "اعتماد وتنفيذ" لحفظها مباشرة في قسم الامتحانات.`;
          }
          suggestedActions.push(
            { label: 'تحويله إلى نسختين A و B', prompt: `حوّل الامتحان الأخير إلى نسختين A و B مع زيادة الصعوبة` },
            { label: 'قسم الامتحانات', navSection: 'exams', navSubAction: 'exams' }
          );
        } else if (call.name === 'place_exam_in_platform') {
          const subject = String(args.subject || 'اللغة العربية');
          const grade = String(args.grade || 'الصف الأول الإعدادي');
          const rawExamText = String(args.rawExamText || cleanMessage);
          const { stage, system } = inferStageAndSystem(grade);
          const questions = await parseRawQuestionsViaGemini(rawExamText, subject, grade);
          const title = String(args.title || `امتحان ${subject} — ${grade}`);

          platformCommand = {
            kind: 'save_exam_direct',
            title,
            examCategory: String(args.examCategory || 'امتحان تدريبي'),
            examPurpose: 'exam',
            stage,
            grade,
            system,
            subject,
            unit: String(args.unit || ''),
            lesson: String(args.lesson || ''),
            durationMinutes: Math.max(10, Number(args.durationMinutes) || 30),
            published: Boolean(args.published),
            alsoAddToBank: args.alsoAddToBank !== false,
            questions,
          };

          replyText = `تم تحليل الامتحان وتنظيم **${questions.length} سؤال** بإجاباتها وتوزيعها على قسم الامتحانات (${grade} — ${subject}).\nاضغط **"اعتماد وتنفيذ في المكان الصحيح"** لوضعه فوراً في قسم الامتحانات${args.alsoAddToBank !== false ? ' وبنك الأسئلة' : ''}.`;
          suggestedActions.push(
            { label: 'فتح قسم الامتحانات', navSection: 'exams', navSubAction: 'exams' },
            { label: 'فتح بنك الأسئلة', navSection: 'question_bank', navSubAction: 'bank' }
          );
        } else if (call.name === 'add_questions_to_bank') {
          const subject = String(args.subject || 'اللغة العربية');
          const grade = String(args.grade || 'الصف الأول الإعدادي');
          const rawQuestionsText = String(args.rawQuestionsText || cleanMessage);
          const questions = await parseRawQuestionsViaGemini(rawQuestionsText, subject, grade);

          platformCommand = {
            kind: 'import_question_bank',
            grade,
            subject,
            unit: String(args.unit || ''),
            lesson: String(args.lesson || ''),
            sourceTitle: String(args.sourceTitle || 'استيراد عبر المساعد الذكي'),
            questions,
          };

          replyText = `تم استخراج وتصنيف **${questions.length} سؤال** جاهزة للإدراج في **بنك الأسئلة** (${grade} · ${subject}).\nراجع الأسئلة في البطاقة أدناه واضغط **"اعتماد وتنفيذ"** لحفظها فوراً.`;
          suggestedActions.push(
            { label: 'فتح بنك الأسئلة', navSection: 'question_bank', navSubAction: 'bank' },
            { label: 'إنشاء امتحان من هذه الأسئلة', prompt: `اعمل امتحان من بنك الأسئلة في ${subject} للصف ${grade}` }
          );
        } else if (call.name === 'save_content_to_library') {
          const subject = String(args.subject || 'اللغة العربية');
          const grade = String(args.grade || 'الصف الأول الإعدادي');
          const { stage, system } = inferStageAndSystem(grade);
          const folder = String(args.folder || 'المناهج الأساسية');
          const title = String(args.title || `محتوى ${subject} — ${grade}`);

          platformCommand = {
            kind: 'save_library_direct',
            title,
            stage,
            grade,
            system,
            subject,
            unit: String(args.unit || ''),
            lesson: String(args.lesson || ''),
            contentType: String(args.contentType || 'شرح'),
            folder,
            extractedText: String(args.extractedText || cleanMessage),
            sharedWithStudents: Boolean(args.sharedWithStudents),
          };

          replyText = `تم تجهيز "${title}" لوضعه في **المكتبة التعليمية** داخل قسم/مجلد **"${folder}"** (${grade} · ${subject}).\nاضغط **"اعتماد وتنفيذ"** للحفظ الفوري.`;
          suggestedActions.push({ label: 'فتح المكتبة التعليمية', navSection: 'library' });
        } else if (call.name === 'add_platform_section_or_band') {
          const settingAction = String(args.settingAction || 'create_band') as
            | 'add_subject'
            | 'add_library_folder'
            | 'add_exam_category'
            | 'add_stage'
            | 'add_system'
            | 'create_band'
            | 'add_band_item';
          const label = String(args.label || '').trim();
          const targetArea =
            args.targetArea === 'students' || args.targetArea === 'exams' || args.targetArea === 'library'
              ? args.targetArea
              : 'general';

          platformCommand = {
            kind: 'add_custom_band_or_setting',
            settingAction,
            label: label || 'قسم جديد',
            value: args.value ? String(args.value) : undefined,
            targetArea,
            bandTitle: args.bandTitle ? String(args.bandTitle) : undefined,
            description: args.description ? String(args.description) : undefined,
          };

          const actionDesc =
            settingAction === 'add_subject'
              ? `إضافة مادة دراسية جديدة باسم "${label}" لتظهر في الامتحانات والمكتبة والطلاب`
              : settingAction === 'add_library_folder'
              ? `إضافة قسم/مجلد جديد في المكتبة باسم "${label}"`
              : settingAction === 'add_exam_category'
              ? `إضافة تصنيف امتحان جديد باسم "${label}"`
              : settingAction === 'add_stage'
              ? `إضافة مرحلة تعليمية جديدة باسم "${label}"`
              : settingAction === 'add_system'
              ? `إضافة نظام تعليمي جديد باسم "${label}"`
              : settingAction === 'add_band_item'
              ? `إضافة بند جديد "${label}" داخل قسم "${String(args.bandTitle || 'القسم المخصص')}"`
              : `إنشاء قسم/بند مخصص جديد بالمنصة باسم "${label}"`;

          replyText = `تم تجهيز طلب **${actionDesc}**.\nاضغط **"اعتماد وتنفيذ"** لتفعيل الإضافة فوراً في المنصة وقاعدة البيانات.`;
          suggestedActions.push(
            {
              label:
                settingAction === 'add_library_folder'
                  ? 'فتح المكتبة التعليمية'
                  : settingAction === 'add_exam_category'
                  ? 'فتح الامتحانات'
                  : 'فتح الإعدادات والأقسام المخصصة',
              navSection:
                settingAction === 'add_library_folder'
                  ? 'library'
                  : settingAction === 'add_exam_category'
                  ? 'exams'
                  : 'settings',
            }
          );
        } else if (call.name === 'manage_registration_or_group_or_announcement') {
          const actionType = String(args.actionType || '');
          const pendingList = Array.isArray((platformSnapshot as { pendingJoinRequests?: unknown[] } | undefined)?.pendingJoinRequests)
            ? (platformSnapshot as {
                pendingJoinRequests: Array<{
                  id: string;
                  studentName: string;
                  parentName: string;
                  parentPhone: string;
                  stage?: string;
                  grade: string;
                  system?: string;
                  subject: string;
                  preferredGroupId?: string;
                  notes?: string;
                }>;
              }).pendingJoinRequests
            : [];

          if (actionType === 'approve_join_request' || actionType === 'reject_join_request') {
            const target = String(args.targetStudentName || '').trim();
            const matched = target
              ? pendingList.filter((r) => r.studentName.includes(target) || target.includes(r.studentName))
              : pendingList;

            if (matched.length === 0) {
              replyText =
                pendingList.length === 0
                  ? 'لا توجد حالياً أي طلبات تسجيل طلاب معلقة بانتظار المراجعة.'
                  : `لم أجد طلب تسجيل باسم "${target}". الطلبات المعلقة الحالية: ${pendingList.map((p) => p.studentName).join('، ')}.`;
            } else {
              const mode = actionType === 'reject_join_request' ? 'reject' : 'approve';
              platformCommand = {
                kind: 'approve_join_request',
                mode,
                requests: matched.map((r) => ({
                  requestId: r.id,
                  studentName: r.studentName,
                  parentName: r.parentName,
                  parentPhone: r.parentPhone,
                  stage: r.stage || inferStageAndSystem(r.grade).stage,
                  grade: r.grade,
                  system: r.system || 'التربية والتعليم',
                  subject: r.subject,
                  monthlyFee: 250,
                  notes: r.notes,
                })),
              };
              replyText =
                mode === 'approve'
                  ? `تم تجهيز قبول **${matched.length} طلب تسجيل** (${matched.map((m) => m.studentName).join('، ')}) وتسجيلهم في صفحة الطلاب مع توليد أكواد البوابة تلقائياً.`
                  : `تم تجهيز رفض طلب التسجيل لـ: ${matched.map((m) => m.studentName).join('، ')}.`;
            }
            suggestedActions.push({ label: 'فتح طلبات التسجيل بالطلاب', navSection: 'students', navSubAction: 'join_requests' });
          } else if (actionType === 'create_group') {
            const grade = String(args.grade || 'الصف الأول الإعدادي');
            const { stage, system } = inferStageAndSystem(grade);
            const subject = String(args.subject || 'اللغة العربية');
            const gName = String(args.groupName || `${grade} - ${subject}`);
            platformCommand = {
              kind: 'create_group',
              name: gName,
              stage,
              grade,
              system: String(args.system || system),
              subject,
              monthlyFee: Number(args.monthlyFee) > 0 ? Number(args.monthlyFee) : 250,
              scheduleSummary: args.scheduleSummary ? String(args.scheduleSummary) : undefined,
            };
            replyText = `تم تجهيز إنشاء مجموعة دراسية جديدة: **"${gName}"** (${grade} · ${subject}). اضغط **"اعتماد وتنفيذ"** لحفظها.`;
            suggestedActions.push({ label: 'فتح المجموعات', navSection: 'students', navSubAction: 'groups' });
          } else if (actionType === 'publish_announcement') {
            const targetType =
              args.targetType === 'group' || args.targetType === 'grade' || args.targetType === 'parents'
                ? args.targetType
                : 'all';
            platformCommand = {
              kind: 'publish_announcement',
              title: String(args.announcementTitle || 'تنبيه هام من الأستاذ'),
              body: String(args.announcementBody || cleanMessage),
              category: 'عام',
              targetType,
              pinned: false,
            };
            replyText = `تم تجهيز الإعلان للنشر في بوابة الطلاب وأولياء الأمور بعنوان: **"${String(args.announcementTitle || 'تنبيه هام من الأستاذ')}"**. اضغط **"اعتماد وتنفيذ"** للنشر.`;
            suggestedActions.push({ label: 'فتح الإعلانات', navSection: 'announcements' });
          } else if (actionType === 'add_schedule_slot') {
            const grade = String(args.grade || 'الصف الأول الإعدادي');
            const subject = String(args.subject || 'اللغة العربية');
            const day = String(args.dayOfWeek || 'السبت');
            platformCommand = {
              kind: 'add_schedule_slot',
              dayOfWeek: day,
              startTime: String(args.startTime || '16:00'),
              endTime: String(args.endTime || '17:30'),
              groupId: '',
              groupName: String(args.groupName || `${grade} - ${subject}`),
              subject,
              grade,
              notes: args.notes ? String(args.notes) : undefined,
            };
            replyText = `تم تجهيز موعد حصة جديد في الجدول يوم **${day}** (${String(args.startTime || '16:00')} - ${String(args.endTime || '17:30')}). اضغط **"اعتماد وتنفيذ"** للحفظ.`;
            suggestedActions.push({ label: 'فتح الجدول والحضور', navSection: 'schedule_attendance', navSubAction: 'schedule' });
          }
        } else if (call.name === 'draft_lesson_study_guide') {
          const title = String(args.title || `مذكرة درس: ${args.lesson || args.subject}`);
          const subject = String(args.subject || 'اللغة العربية');
          const grade = String(args.grade || 'الصف الأول الإعدادي');
          const lesson = String(args.lesson || title);
          const focusPoints = Array.isArray(args.focusPoints) ? (args.focusPoints as string[]) : [];

          const guideResp = await ai.models.generateContent({
            model: 'gemini-4-hydrogen',
            contents: `أعد مذكرة تعليمية احترافية ومنظمة بالعربية للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜 وفق المنهج المصري:
- العنوان: ${title}
- المادة: ${subject}
- الصف: ${grade}
- الدرس: ${lesson}
${focusPoints.length > 0 ? `- المحاور المطلوبة: ${focusPoints.join('، ')}` : ''}
- طلب المعلم: ${cleanMessage}

اجعل المذكرة تشمل:
1. أهداف الدرس ونقاط الفهم الرئيسية.
2. الشرح المبسط والمنظم بأمثلة واضحة.
3. أهم الأسئلة المتوقعة (بم تفسر / استخرج / اختر) بإجاباتها النموذجية.
4. نصيحة سريعة للطالب وتنبيه لأشهر الأخطاء الشائعة.`,
          });

          const guideMarkdown = (guideResp.text || '').trim();
          const { stage, system } = inferStageAndSystem(grade);
          draftExamArtifact = {
            kind: 'summary',
            title,
            stage,
            grade,
            system,
            subject,
            unit: '',
            lesson,
            questionCount: 0,
            variantsCount: 1,
            includeAnswerKey: true,
            questions: [],
            bodyMarkdown: guideMarkdown,
            sourceLibraryIds: [],
            reviewNotes: ['مذكرة تعليمية منسقة مولّدة عبر محرك Gemini التربوي.'],
          };
          replyText = guideMarkdown || `تم إعداد "${title}" بنجاح، ويمكنك الآن حفظها في المكتبة أو تصديرها Word.`;
          suggestedActions.push(
            { label: `اعمل امتحان 10 أسئلة على ${lesson}`, prompt: `اعمل امتحان ${subject} 10 أسئلة للصف ${grade} على درس ${lesson}` },
            { label: 'المكتبة التعليمية', navSection: 'library' }
          );
        }
      }

      if (!replyText) {
        replyText = 'لم يرجع النموذج نصاً مكتوباً لهذه المحاولة؛ حاول إعادة صياغة سؤالك بتحديد أكثر.';
      }

      if (suggestedActions.length === 0) {
        if (cleanMessage.includes('غياب') || cleanMessage.includes('غاب')) {
          suggestedActions.push(
            { label: 'صياغة رسالة واتساب لولي الأمر', prompt: 'اكتب رسالة واتساب لطيفة ومهنية لأولياء أمور الطلاب المتغيبين' },
            { label: 'سجل الحضور والجدول', navSection: 'schedule_attendance', navSubAction: 'attendance' }
          );
        } else if (cleanMessage.includes('مالي') || cleanMessage.includes('دفع') || cleanMessage.includes('مصروف')) {
          suggestedActions.push(
            { label: 'مين مادفعش الشهر ده؟', prompt: 'اعرض قائمة الطلاب غير المسددين للشهر الحالي' },
            { label: 'قسم المدفوعات والمالية', navSection: 'payments' }
          );
        } else if (cleanMessage.includes('تسجيل') || cleanMessage.includes('انضمام') || cleanMessage.includes('قسم') || cleanMessage.includes('بند')) {
          suggestedActions.push(
            { label: 'عرض طلبات التسجيل المعلقة', navSection: 'students', navSubAction: 'join_requests' },
            { label: 'فتح الإعدادات والأقسام المخصصة', navSection: 'settings', navSubAction: 'general' }
          );
        } else {
          suggestedActions.push(
            { label: 'ملخص حالة المنصة اليوم', prompt: 'لخّص وضع المنصة اليوم: الحصص، الغياب، المالية، والمهام العاجلة' },
            { label: 'مين أكتر طلاب متفوقين ومين محتاج متابعة؟', prompt: 'حلل أداء الطلاب: مين المتفوقين ومين محتاج متابعة عاجلة؟' }
          );
        }
      }

      res.json({
        reply: replyText,
        model: 'gemini-4-hydrogen',
        draftExamArtifact,
        platformCommand,
        suggestedActions,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('Smart Agent API error:', err);
      if (msg === 'GEMINI_API_KEY_MISSING') {
        res.status(503).json({
          error: 'مفتاح Gemini API غير مُعد على الخادم. يعمل المساعد بالتحليل المحلي العميق دون إنترنت.',
        });
        return;
      }
      res.status(500).json({ error: `تعذر معالجة الطلب عبر Gemini: ${msg}` });
    }
  });

  // Generate Targeted Remedial Drill for Weak Lessons/Skills
  app.post('/api/ai/generate-remedial', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'إنشاء التدريبات العلاجية مخصص للمدرس.' });
        return;
      }
      const { subject, grade, weakLessons, weakSkills, missedPrompts, sourceText, count } = req.body as {
        subject: string;
        grade: string;
        weakLessons: string[];
        weakSkills: string[];
        missedPrompts: string[];
        sourceText?: string;
        count?: number;
      };
      const qCount = Math.min(15, Math.max(4, Number(count) || 6));
      const gen = await generateStructuredQuestions({
        stage: 'عام',
        grade: grade || 'الصف الأول الإعدادي',
        system: 'التربية والتعليم',
        subject: subject || 'اللغة العربية',
        lesson: (weakLessons || []).join('، '),
        sourceText:
          sourceText ||
          `دروس تحتاج علاجاً: ${(weakLessons || []).join('، ')}\nمهارات: ${(weakSkills || []).join('، ')}\nأخطاء سابقة: ${(missedPrompts || []).slice(0, 6).join(' | ')}`,
        questionCount: qCount,
        questionTypes: ['اختر الإجابة الصحيحة', 'صح وخطأ', 'أكمل'],
        totalMarks: qCount,
        strictSourceOnly: false,
        difficultyMix: { easy: 45, medium: 40, hard: 15 },
        targetSkills: weakSkills,
        excludePrompts: missedPrompts,
      });
      res.json({ questions: gen.questions });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر توليد التدريب العلاجي: ${msg}` });
    }
  });

  // Adaptive Smart Training Endpoint for Students (never exposes teacher questionBank/answer keys)
  app.post('/api/student/adaptive-drill', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const {
        grade,
        system,
        subject,
        lesson,
        targetSkills,
        difficulty,
        count,
        excludePrompts,
      } = req.body as {
        grade?: string;
        system?: string;
        subject?: string;
        lesson?: string;
        targetSkills?: string[];
        difficulty?: 'easy' | 'medium' | 'hard';
        count?: number;
        excludePrompts?: string[];
      };

      const qCount = Math.min(10, Math.max(3, Number(count) || 5));
      const diffMix =
        difficulty === 'hard'
          ? { easy: 10, medium: 30, hard: 60 }
          : difficulty === 'easy'
          ? { easy: 65, medium: 25, hard: 10 }
          : { easy: 25, medium: 50, hard: 25 };

      const gen = await generateStructuredQuestions({
        stage: 'عام',
        grade: grade || 'الصف الأول الإعدادي',
        system: system || 'التربية والتعليم',
        subject: subject || 'اللغة العربية',
        lesson: lesson || 'مراجعة عامة وتطبيقات',
        sourceText: `تدريب ذكي تكيفي للطالب في مادة ${subject || 'اللغة العربية'} للصف ${grade || 'الصف الأول الإعدادي'}${
          lesson ? ` — درس: ${lesson}` : ''
        }. ركز على الفهم والتطبيق مع شروحات تعليمية واضحة لكل سؤال.`,
        questionCount: qCount,
        questionTypes: ['اختر الإجابة الصحيحة', 'صح وخطأ'],
        totalMarks: qCount,
        strictSourceOnly: false,
        difficultyMix: diffMix,
        targetSkills: Array.isArray(targetSkills) && targetSkills.length > 0 ? targetSkills : undefined,
        excludePrompts: Array.isArray(excludePrompts) ? excludePrompts.slice(0, 20) : undefined,
      });

      res.json({ questions: gen.questions });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg === 'GEMINI_API_KEY_MISSING') {
        res.status(503).json({ error: 'خدمة التوليد الذكي غير مفعلة حالياً.' });
        return;
      }
      res.status(500).json({ error: `تعذر تجهيز التدريب الذكي: ${msg}` });
    }
  });

  // 1. Auto-Classify Pasted Educational Text & Build Full Lesson + Exam + Interactive Kit
  app.post('/api/ai/analyze-and-build', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'هذه الأداة مخصصة للمعلم فقط.' });
        return;
      }
      const { rawText, questionCount, questionTypes } = req.body as {
        rawText: string;
        questionCount?: number;
        questionTypes?: string[];
      };
      if (!rawText || rawText.trim().length < 20) {
        res.status(400).json({ error: 'يرجى لصق نص تعليمي كافٍ للتحليل (20 حرفاً على الأقل).' });
        return;
      }

      const ai = getGeminiClient();
      const qCount = Math.min(25, Math.max(4, Number(questionCount) || 8));
      const typesList =
        Array.isArray(questionTypes) && questionTypes.length > 0
          ? questionTypes
          : ['اختر الإجابة الصحيحة', 'صح وخطأ', 'أكمل', 'بم تفسر؟', 'أسئلة مقالية'];

      const prompt = `أنت خبير مناهج مصرية للأستاذ "𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜" (اللغة العربية، الدراسات الاجتماعية، التاريخ، التربوي / الدبلومة التربوية).
قم بتحليل النص التعليمي التالي، وحدد بدقة أوتوماتيكية:
1. المرحلة (من: المرحلة الابتدائية، المرحلة الإعدادية، المرحلة الثانوية، الدبلومة التربوية (التربوي))
2. الصف الدراسي (مثل: الصف الرابع الابتدائي .. حتى الصف الثالث الثانوي، أو الدبلومة التربوية العامة (نظام السنة الواحدة))
3. النظام (التربية والتعليم، الأزهر الشريف، الثانوية العامة، البكالوريا، الدبلومة التربوية)
4. المادة (اللغة العربية، الدراسات الاجتماعية، التاريخ، التربوي)
5. الوحدة واسم الدرس وعنوان مقترح مناسب.
6. ملخص منظم للدرس + أهداف تعليمية + مفاهيم/شخصيات/تواريخ أساسية + واجب منزلي مقترح.
7. قائمة متنوعة من ${qCount} سؤالاً بالأنواع المطلوبة (${typesList.join('، ')}) تجمع بين الاختيار من متعدد والصح والخطأ والمقالي مع الإجابة النموذجية والشرح والمهارة ومستوى الصعوبة.
8. مسودة نشاط تفاعلي قصير (4 عناصر بطاقات مراجعة أو توصيل أو ترتيب).

النص التعليمي:
"""
${rawText.slice(0, 14000)}
"""`;

      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: prompt,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              detected: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  stage: { type: Type.STRING },
                  grade: { type: Type.STRING },
                  system: { type: Type.STRING },
                  subject: { type: Type.STRING },
                  unit: { type: Type.STRING },
                  lesson: { type: Type.STRING },
                  confidenceReason: { type: Type.STRING },
                },
                required: ['title', 'stage', 'grade', 'system', 'subject', 'unit', 'lesson'],
              },
              lessonPrep: {
                type: Type.OBJECT,
                properties: {
                  summary: { type: Type.STRING },
                  objectives: { type: Type.ARRAY, items: { type: Type.STRING } },
                  keyConcepts: { type: Type.ARRAY, items: { type: Type.STRING } },
                  homeworkPrompt: { type: Type.STRING },
                },
                required: ['summary', 'objectives', 'keyConcepts', 'homeworkPrompt'],
              },
              questions: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    type: { type: Type.STRING },
                    prompt: { type: Type.STRING },
                    options: { type: Type.ARRAY, items: { type: Type.STRING } },
                    correctAnswer: { type: Type.STRING },
                    explanation: { type: Type.STRING },
                    points: { type: Type.NUMBER },
                    difficulty: { type: Type.STRING },
                    skill: { type: Type.STRING },
                  },
                  required: ['type', 'prompt', 'correctAnswer', 'explanation'],
                },
              },
              interactiveActivityDraft: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  activityType: { type: Type.STRING },
                  items: {
                    type: Type.ARRAY,
                    items: {
                      type: Type.OBJECT,
                      properties: {
                        label: { type: Type.STRING },
                        answer: { type: Type.STRING },
                        hint: { type: Type.STRING },
                        orderIndex: { type: Type.NUMBER },
                      },
                    },
                  },
                },
              },
            },
            required: ['detected', 'lessonPrep', 'questions'],
          },
        },
      });

      const parsed = JSON.parse(response.text || '{}') as {
        detected: Record<string, string>;
        lessonPrep: Record<string, unknown>;
        questions?: Array<Partial<GeneratedQuestionItem>>;
        interactiveActivityDraft?: {
          title?: string;
          activityType?: string;
          items?: Array<{ label?: string; answer?: string; hint?: string; orderIndex?: number }>;
        };
      };

      const formattedQuestions = (parsed.questions || []).map((q, idx) => ({
        id: `ab_${Date.now().toString(36)}_${idx}`,
        type: q.type || 'اختر الإجابة الصحيحة',
        prompt: q.prompt || '',
        options: Array.isArray(q.options) ? q.options : [],
        correctAnswer: q.correctAnswer || '',
        explanation: q.explanation || '',
        points: Number(q.points) || 1,
        difficulty: (q.difficulty === 'easy' || q.difficulty === 'hard' ? q.difficulty : 'medium') as 'easy' | 'medium' | 'hard',
        skill: q.skill || 'الفهم والاستيعاب',
        unit: parsed.detected?.unit || '',
        lesson: parsed.detected?.lesson || '',
      }));

      res.json({
        detected: parsed.detected,
        lessonPrep: parsed.lessonPrep,
        questions: formattedQuestions,
        interactiveActivityDraft: parsed.interactiveActivityDraft
          ? {
              title: parsed.interactiveActivityDraft.title || `نشاط: ${parsed.detected?.lesson || 'الدرس'}`,
              activityType:
                parsed.interactiveActivityDraft.activityType === 'term_match' ||
                parsed.interactiveActivityDraft.activityType === 'timeline_order'
                  ? parsed.interactiveActivityDraft.activityType
                  : 'flashcards',
              items: (parsed.interactiveActivityDraft.items || []).map((it, idx) => ({
                id: `act_it_${idx}`,
                label: it.label || '',
                answer: it.answer || '',
                hint: it.hint || '',
                orderIndex: it.orderIndex || idx + 1,
              })),
            }
          : undefined,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر تحليل النص تلقائياً: ${msg}` });
    }
  });

  // 1b. Specialized ChatGPT-Style Curriculum & Book Ingestion Assistant (Auto-Classify + Atomic Split + Conversational Refinement)
  app.post('/api/ai/ingest-curriculum', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'مساعد إدخال الكتب والمناهج مخصص للمعلم فقط.' });
        return;
      }

      const {
        rawText,
        instruction,
        fileName,
        availableSubjects,
        currentClassification,
        previousLessons,
        chatHistory,
      } = req.body as {
        rawText?: string;
        instruction?: string;
        fileName?: string;
        availableSubjects?: string[];
        currentClassification?: {
          stage?: string;
          grade?: string;
          system?: string;
          subject?: string;
          contentType?: string;
          folder?: string;
        };
        previousLessons?: Array<{
          id?: string;
          title?: string;
          unit?: string;
          lesson?: string;
          lessonOrder?: number;
          summary?: string;
          keyConcepts?: string[];
          extractedText?: string;
        }>;
        chatHistory?: Array<{ role: 'user' | 'assistant'; text: string }>;
      };

      const cleanText = String(rawText || '').trim();
      const cleanInstruction = String(instruction || '').trim();
      if (cleanText.length < 15 && cleanInstruction.length < 4 && (!previousLessons || previousLessons.length === 0)) {
        res.status(400).json({ error: 'يرجى كتابة نص تعليمي أو تعليمات أو إرفاق ملف ليتمكن المساعد من تحليله.' });
        return;
      }

      const VALID_STAGES = [
        'رياض الأطفال (KG)',
        'المرحلة الابتدائية',
        'المرحلة الإعدادية',
        'المرحلة الثانوية',
        'الدبلومة التربوية (التربوي)',
        'تأسيس وتأهيل خاص / أخرى',
      ];
      const VALID_GRADES_MAP: Record<string, string[]> = {
        'رياض الأطفال (KG)': ['KG 1 (المستوى الأول)', 'KG 2 (المستوى الثاني)'],
        'المرحلة الابتدائية': [
          'الصف الأول الابتدائي',
          'الصف الثاني الابتدائي',
          'الصف الثالث الابتدائي',
          'الصف الرابع الابتدائي',
          'الصف الخامس الابتدائي',
          'الصف السادس الابتدائي',
        ],
        'المرحلة الإعدادية': ['الصف الأول الإعدادي', 'الصف الثاني الإعدادي', 'الصف الثالث الإعدادي'],
        'المرحلة الثانوية': ['الصف الأول الثانوي', 'الصف الثاني الثانوي', 'الصف الثالث الثانوي'],
        'الدبلومة التربوية (التربوي)': [
          'الدبلومة التربوية العامة (نظام السنة الواحدة)',
          'الدبلومة التربوية التخصصية / المهنية',
          'دبلومة تربوية - مسار التربوي والأساليب',
        ],
        'تأسيس وتأهيل خاص / أخرى': [
          'تأسيس القراءة والكتابة والنحو',
          'مراجعة وتأهيل عام',
          'مرحلة أو صف مخصص (يُذكر في الملاحظات)',
        ],
      };
      const VALID_SYSTEMS = [
        'الأزهر الشريف',
        'التربية والتعليم',
        'الثانوية العامة',
        'البكالوريا',
        'الدبلومة التربوية',
      ];
      const SUBJECTS_LIST = Array.from(
        new Set([
          'اللغة العربية',
          'الدراسات الاجتماعية',
          'التاريخ',
          'التربوي',
          ...(Array.isArray(availableSubjects) ? availableSubjects.filter((s) => typeof s === 'string' && s.trim()) : []),
        ])
      );
      const VALID_CONTENT_TYPES = [
        'شرح',
        'واجب',
        'أسئلة',
        'مراجعة',
        'كتاب',
        'ملخص',
        'بنك أسئلة',
        'أنشطة تعليمية',
      ];

      const historyBlock = Array.isArray(chatHistory) && chatHistory.length > 0
        ? `\nسجل المحادثة السابق مع المعلم:\n${chatHistory
            .slice(-6)
            .map((h) => `- ${h.role === 'user' ? 'المعلم' : 'المساعد'}: ${String(h.text || '').slice(0, 600)}`)
            .join('\n')}`
        : '';

      const previousDraftBlock = Array.isArray(previousLessons) && previousLessons.length > 0
        ? `\nالمسودة الحالية للدروس الذرية (التي قد يطلب المعلم تعديلها أو إعادة تقسيمها):\n${JSON.stringify(
            {
              classification: currentClassification || {},
              lessons: previousLessons.slice(0, 15).map((l) => ({
                title: l.title,
                unit: l.unit,
                lesson: l.lesson,
                lessonOrder: l.lessonOrder,
                summary: l.summary,
                keyConcepts: l.keyConcepts,
                extractedTextSnippet: String(l.extractedText || '').slice(0, 2200),
              })),
            },
            null,
            2
          )}`
        : '';

      const prompt = `أنت المساعد الذكي المتخصص في إدارة وتصنيف الكتب والمناهج التعليمية للأستاذ "𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜" (نظام ChatGPT للكتب والدروس + النظام الذري للوحدات والدروس).

مهمتك الأساسية:
1. قراءة النص التعليمي أو محتوى الكتاب/الملف المرفق، مع مراعاة **تعليمات المعلم الصريحة** بأعلى أولوية (مثلاً إذا قال المعلم: "مصر ده تبع الدرس الأول" أو "ده تبع رابعة ابتدائي" أو "اجمعهم في درس واحد" أو "قسّمهم إلى دروس").
2. تحديد المسار التعليمي الدقيق تلقائياً بالاختيار الحصري من قوائم المنصة التالية:
   - المراحل المسموحة (stage): ${VALID_STAGES.join(' | ')}
   - الصفوف المسموحة لكل مرحلة (grade): ${JSON.stringify(VALID_GRADES_MAP)}
   - الأنظمة المسموحة (system): ${VALID_SYSTEMS.join(' | ')}
   - المواد المتاحة (subject): ${SUBJECTS_LIST.join(' | ')}
   - أنواع المحتوى المسموحة (contentType): ${VALID_CONTENT_TYPES.join(' | ')}
   - اسم المجلد (folder): مثلاً "المناهج الأساسية" أو "كتب ومذكرات" أو "مذكرات وكتب التربوي" أو "ملخصات ومراجعات".
   (ملاحظة مهمة: إذا كان المحتوى يخص أصول التربية، علم النفس التربوي، طرق التدريس، التقويم التربوي، أو الدبلومة التربوية فاجعل stage = "الدبلومة التربوية (التربوي)" و system = "الدبلومة التربوية" و subject = "التربوي").
   - **قاعدة تقييم الثقة والوضوح**:
     • إذا كان النص يحتوي على إشارة واضحة للمرحلة والصف والمادة (مثل اسم درس معروف في المنهج المصري أو توجيه واضح من المعلم)، اجعل confidence = "high" و needsClarification = false.
     • إذا كان النص قصيراً أو عاماً أو قد يصلح لأكثر من صف دراسي أو مادة ولم يذكر المعلم الصف صراحةً، اجعل confidence = "low" أو "medium"، واجعل needsClarification = true، واكتب clarificationQuestion سؤالاً ودوداً بالعامية المصرية/العربية الواضحة يسأل المعلم: "النص ده تبع أي صف دراسي ومادة بالضبط؟"، مع وضع 2 إلى 4 خيارات مرشحة دقيقة في candidateChoices (كل خيار يحتوي على label واضح مثل "الصف الأول الإعدادي — الدراسات الاجتماعية" مع stage و grade و system و subject و unit و lesson مقترحين).
3. تطبيق **التقسيم الذري الذكي (Atomic Lesson Splitting)**:
   - إذا كان النص المرسل يخص درساً واحداً فقط أو أشار المعلم لدرس محدد (مثل: "الدرس الأول" عن مصر)، أنشئ ذرة تعليمية واحدة متكاملة واضبط حقل unit (مثلاً "الوحدة الأولى") وحقل lesson (مثلاً "الدرس الأول: موقع مصر وأهميته" أو حسب العنوان الدقيق) وحافظ على **النص التعليمي الكامل حرفياً** دون حذف المعلومات أو التواريخ أو القواعد داخل extractedText.
   - إذا كان النص عبارة عن كتاب أو ملزمة تحتوي على عدة دروس أو وحدات واضحة (مثلاً الدرس الأول والدرس الثاني والدرس الثالث)، فقم بتقسيمه تلقائياً إلى عدة ذرات دروس (بحد أقصى 12 ذرة في المرة الواحدة)، بحيث يحتوي كل عنصر في lessons على النص الكامل الخاص بهذا الدرس فقط، مع unit و lesson و lessonOrder بالترتيب الصحيح، حتى يتمكن المعلم في مصنع الامتحانات من الضغط على أي درس (مثل الدرس الأول) لتوليد امتحان يعتمد على كل النصوص المحفوظة تحت هذا الدرس تلقائياً.
   - إذا كانت هذه رسالة متابعة/تعديل على مسودة سابقة دون لصق نص جديد، طبّق تعديلات المعلم على currentClassification و previousLessons وأرجع النصوص كاملة من المسودة السابقة مع التحديث المطلوب.
4. لكل ذرة درس: استخرج summary موجز و keyConcepts (أهم 3-7 مفاهيم/قواعد/شخصيات/تواريخ) و suggestedQuestionPrompts (سؤالين مقترحين سريعي المعاينة).
5. اكتب assistantReply بأسلوب احترافي ودود وواضح بالعربية يوضح للمعلم: ماذا قرأت، وأي مسار تم اختياره، ولماذا، وكيف تم تقسيم الدروس الذرية، مع 2-3 followUpSuggestions قصيرة للخطوة التالية.

${fileName ? `اسم الملف المرفق: ${fileName}` : ''}
${cleanInstruction ? `تعليمات المعلم المباشرة:\n"${cleanInstruction}"` : ''}
${historyBlock}
${previousDraftBlock}

${cleanText ? `النص التعليمي المرسل (يُحفظ جوهره بالكامل داخل ذرات الدروس):\n"""\n${cleanText.slice(0, 52000)}\n"""` : ''}`;

      const ai = getGeminiClient();
      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: prompt,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              assistantReply: { type: Type.STRING },
              classification: {
                type: Type.OBJECT,
                properties: {
                  stage: { type: Type.STRING },
                  grade: { type: Type.STRING },
                  system: { type: Type.STRING },
                  subject: { type: Type.STRING },
                  contentType: { type: Type.STRING },
                  folder: { type: Type.STRING },
                  reasoning: { type: Type.STRING },
                  confidence: { type: Type.STRING },
                  needsClarification: { type: Type.BOOLEAN },
                  clarificationQuestion: { type: Type.STRING },
                  candidateChoices: {
                    type: Type.ARRAY,
                    items: {
                      type: Type.OBJECT,
                      properties: {
                        label: { type: Type.STRING },
                        stage: { type: Type.STRING },
                        grade: { type: Type.STRING },
                        system: { type: Type.STRING },
                        subject: { type: Type.STRING },
                        unit: { type: Type.STRING },
                        lesson: { type: Type.STRING },
                      },
                      required: ['label', 'stage', 'grade', 'system', 'subject'],
                    },
                  },
                },
                required: ['stage', 'grade', 'system', 'subject', 'contentType', 'folder', 'reasoning'],
              },
              lessons: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    title: { type: Type.STRING },
                    unit: { type: Type.STRING },
                    lesson: { type: Type.STRING },
                    lessonOrder: { type: Type.NUMBER },
                    summary: { type: Type.STRING },
                    keyConcepts: { type: Type.ARRAY, items: { type: Type.STRING } },
                    extractedText: { type: Type.STRING },
                    suggestedQuestionPrompts: { type: Type.ARRAY, items: { type: Type.STRING } },
                  },
                  required: ['title', 'unit', 'lesson', 'lessonOrder', 'summary', 'keyConcepts', 'extractedText'],
                },
              },
              followUpSuggestions: { type: Type.ARRAY, items: { type: Type.STRING } },
            },
            required: ['assistantReply', 'classification', 'lessons'],
          },
        },
      });

      const parsed = JSON.parse((response.text || '{}').trim()) as {
        assistantReply?: string;
        classification?: {
          stage?: string;
          grade?: string;
          system?: string;
          subject?: string;
          contentType?: string;
          folder?: string;
          reasoning?: string;
          confidence?: string;
          needsClarification?: boolean;
          clarificationQuestion?: string;
          candidateChoices?: Array<{
            label?: string;
            stage?: string;
            grade?: string;
            system?: string;
            subject?: string;
            unit?: string;
            lesson?: string;
          }>;
        };
        lessons?: Array<{
          title?: string;
          unit?: string;
          lesson?: string;
          lessonOrder?: number;
          summary?: string;
          keyConcepts?: string[];
          extractedText?: string;
          suggestedQuestionPrompts?: string[];
        }>;
        followUpSuggestions?: string[];
      };

      const rawClass = parsed.classification || {};
      const pickBest = (val: string | undefined, list: string[], fallback: string): string => {
        const v = String(val || '').trim();
        if (!v) return fallback;
        const exact = list.find((item) => item === v);
        if (exact) return exact;
        const normV = normalizeArabicText(v);
        const fuzzy = list.find((item) => normalizeArabicText(item) === normV || normalizeArabicText(item).includes(normV) || normV.includes(normalizeArabicText(item)));
        return fuzzy || fallback;
      };

      const stage = pickBest(
        rawClass.stage,
        VALID_STAGES,
        currentClassification?.stage && VALID_STAGES.includes(currentClassification.stage)
          ? currentClassification.stage
          : 'المرحلة الإعدادية'
      );
      const validGradesForStage = VALID_GRADES_MAP[stage] || VALID_GRADES_MAP['المرحلة الإعدادية'];
      const grade = pickBest(
        rawClass.grade,
        validGradesForStage,
        currentClassification?.grade && validGradesForStage.includes(currentClassification.grade)
          ? currentClassification.grade
          : validGradesForStage[0]
      );
      const system = pickBest(
        rawClass.system,
        VALID_SYSTEMS,
        stage === 'الدبلومة التربوية (التربوي)' ? 'الدبلومة التربوية' : 'التربية والتعليم'
      );
      const subject = pickBest(
        rawClass.subject,
        SUBJECTS_LIST,
        stage === 'الدبلومة التربوية (التربوي)' ? 'التربوي' : SUBJECTS_LIST[0]
      );
      const contentType = pickBest(rawClass.contentType, VALID_CONTENT_TYPES, fileName ? 'كتاب' : 'شرح');
      const folder = String(rawClass.folder || '').trim() || (stage === 'الدبلومة التربوية (التربوي)' ? 'مذكرات وكتب التربوي' : 'المناهج الأساسية');

      const rawLessons = Array.isArray(parsed.lessons) ? parsed.lessons : [];
      const fallbackText =
        cleanText ||
        (Array.isArray(previousLessons) ? previousLessons.map((l) => l.extractedText || '').join('\n\n') : '') ||
        cleanInstruction;

      const normalizedLessons = (rawLessons.length > 0
        ? rawLessons
        : [
            {
              title: fileName ? fileName.replace(/\.[^/.]+$/, '') : `محتوى ${subject} — ${grade}`,
              unit: 'الوحدة الأولى',
              lesson: 'الدرس الأول',
              lessonOrder: 1,
              summary: 'تم تجهيز المحتوى تلقائياً وحفظ النص بالكامل.',
              keyConcepts: [],
              extractedText: fallbackText,
              suggestedQuestionPrompts: [],
            },
          ]
      ).map((l, idx) => {
        const matchedPrev = Array.isArray(previousLessons) ? previousLessons[idx] : undefined;
        let textContent = String(l.extractedText || '').trim();
        // Ensure full text isn't accidentally lost on single-lesson ingestion
        if (rawLessons.length <= 1 && cleanText.length > 80 && textContent.length < cleanText.length * 0.6) {
          textContent = cleanText;
        } else if (!textContent && matchedPrev?.extractedText) {
          textContent = matchedPrev.extractedText;
        }
        return {
          id: matchedPrev?.id || `atom_${Date.now().toString(36)}_${idx + 1}`,
          title: String(l.title || `الدرس ${idx + 1}`).trim(),
          unit: String(l.unit || 'الوحدة الأولى').trim(),
          lesson: String(l.lesson || `الدرس ${idx + 1}`).trim(),
          lessonOrder: Number(l.lessonOrder) > 0 ? Number(l.lessonOrder) : idx + 1,
          summary: String(l.summary || '').trim(),
          keyConcepts: Array.isArray(l.keyConcepts)
            ? l.keyConcepts.map((c) => String(c).trim()).filter(Boolean).slice(0, 10)
            : [],
          extractedText: textContent || fallbackText,
          suggestedQuestionPrompts: Array.isArray(l.suggestedQuestionPrompts)
            ? l.suggestedQuestionPrompts.map((q) => String(q).trim()).filter(Boolean).slice(0, 4)
            : [],
          selected: true,
        };
      });

      const normalizedConfidence =
        rawClass.confidence === 'high' || rawClass.confidence === 'medium' || rawClass.confidence === 'low'
          ? rawClass.confidence
          : 'high';
      const normalizedCandidates = Array.isArray(rawClass.candidateChoices)
        ? rawClass.candidateChoices
            .slice(0, 5)
            .map((c) => {
              const cStage = pickBest(c.stage, VALID_STAGES, stage);
              const cGrades = VALID_GRADES_MAP[cStage] || VALID_GRADES_MAP['المرحلة الإعدادية'];
              const cGrade = pickBest(c.grade, cGrades, cGrades[0]);
              const cSystem = pickBest(
                c.system,
                VALID_SYSTEMS,
                cStage === 'الدبلومة التربوية (التربوي)' ? 'الدبلومة التربوية' : 'التربية والتعليم'
              );
              const cSubject = pickBest(c.subject, SUBJECTS_LIST, subject);
              return {
                label: String(c.label || `${cGrade} — ${cSubject}`).trim(),
                stage: cStage,
                grade: cGrade,
                system: cSystem,
                subject: cSubject,
                unit: c.unit ? String(c.unit).trim() : undefined,
                lesson: c.lesson ? String(c.lesson).trim() : undefined,
              };
            })
        : [];

      res.json({
        assistantReply:
          String(parsed.assistantReply || '').trim() ||
          `تم تحليل المحتوى وتصنيفه في مسار: ${stage} / ${grade} / ${subject} وتجهيز ${normalizedLessons.length} ذرة تعليمية جاهزة للحفظ.`,
        classification: {
          stage,
          grade,
          system,
          subject,
          contentType,
          folder,
          reasoning: String(rawClass.reasoning || 'تم تحديد المسار تلقائياً بناءً على المحتوى وتوجيهات المعلم.').trim(),
          confidence: normalizedConfidence,
          needsClarification: Boolean(rawClass.needsClarification),
          clarificationQuestion: rawClass.clarificationQuestion
            ? String(rawClass.clarificationQuestion).trim()
            : undefined,
          candidateChoices: normalizedCandidates,
        },
        lessons: normalizedLessons,
        followUpSuggestions: Array.isArray(parsed.followUpSuggestions) && parsed.followUpSuggestions.length > 0
          ? parsed.followUpSuggestions.map((s) => String(s).trim()).filter(Boolean).slice(0, 4)
          : ['تعديل رقم أو اسم الدرس', 'دمج في درس واحد', 'حفظ وتوليد امتحان مباشر'],
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('AI ingest curriculum error:', err);
      if (msg === 'GEMINI_API_KEY_MISSING') {
        res.status(503).json({ error: 'مفتاح Gemini API غير مضاف بعد لتشغيل المساعد الذكي.' });
        return;
      }
      res.status(500).json({ error: `تعذر تحليل وتصنيف المحتوى: ${msg}` });
    }
  });

  // 2. Google Search Grounded Assistant (Web Search + Citations inside platform)
  app.post('/api/ai/google-search', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'بحث جوجل التعليمي مخصص للمعلم.' });
        return;
      }
      const { query: searchQuery, grade, subject } = req.body as {
        query: string;
        grade?: string;
        subject?: string;
      };
      if (!searchQuery || !searchQuery.trim()) {
        res.status(400).json({ error: 'يرجى إدخال عبارة البحث.' });
        return;
      }

      const ai = getGeminiClient();
      const prompt = `أنت مساعد بحث تعليمي مرتبط ببحث جوجل للأستاذ "𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜".
ابحث بدقة في المنهج المصري والمصادر التعليمية الموثوقة عن:
"${searchQuery}"
${grade ? `الصف المستهدف: ${grade}` : ''}
${subject ? `المادة: ${subject}` : ''}

قدم:
1. ملخصاً دقيقاً ومنظماً للمعلومة أو الدرس أو نموذج الأسئلة المطلوب.
2. النقاط الأساسية والتواريخ أو القواعد النحوية المهمة.
3. أمثلة تطبيقية أو أسئلة سريعة مقترحة يمكن تحويلها مباشرة لامتحان.`;

      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: prompt,
        config: {
          tools: [{ googleSearch: {} }],
        },
      });

      const rawChunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks || [];
      const citations = rawChunks
        .map((ch) => (ch as { web?: { uri?: string; title?: string } }).web)
        .filter((w): w is { uri: string; title?: string } => Boolean(w?.uri))
        .map((w) => ({
          title: w.title || w.uri,
          uri: w.uri,
        }));

      res.json({
        answer: response.text || '',
        citations,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر إتمام البحث عبر جوجل: ${msg}` });
    }
  });

  // 3. Ubiquitous Google AI Auditor & Edit Suggester (Exams, Bank, Study Notes, Revisions)
  app.post('/api/ai/audit-content', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'مراجعة المحتوى مخصصة للمعلم.' });
        return;
      }
      const { mode, title, subject, grade, text, items } = req.body as {
        mode: 'exam' | 'question_bank' | 'library_note' | 'revision';
        title?: string;
        subject?: string;
        grade?: string;
        text?: string;
        items?: Array<{
          id: string;
          type?: string;
          prompt: string;
          options?: string[];
          correctAnswer?: string;
          explanation?: string;
        }>;
      };

      const ai = getGeminiClient();
      const contentBlock =
        mode === 'library_note' || mode === 'revision'
          ? `النص للمراجعة (${title || 'مذكرة'} - ${subject || ''} - ${grade || ''}):\n"""\n${(text || '').slice(0, 14000)}\n"""`
          : `الأسئلة للمراجعة (${title || 'امتحان'} - ${subject || ''} - ${grade || ''}):\n${JSON.stringify((items || []).slice(0, 40), null, 2)}`;

      const prompt = `أنت "المراجع والمفتش التعليمي الذكي" للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜.
افحص المحتوى التالي بدقة (علمياً، تاريخياً، إملائياً، نحوياً، تربوياً) واكتشف أي أخطاء (معلومات تاريخية أو جغرافية غير دقيقة، تواريخ أو أرقام مغلوطة، أخطاء إملائية أو نحوية، غموض في الصياغة، تكرار خيارات، وجود أكثر من إجابة محتملة، أو عدم تطابق الإجابة النموذجية مع السؤال).
لكل ملاحظة تجدها:
- حدد \`targetId\` (نفس id العنصر أو "note_text" للنص الكامل).
- حدد \`category\` ("خطأ مؤكد" | "احتمال خطأ" | "يحتاج إلى مراجعة" | "ملاحظة لغوية" | "ملاحظة تربوية" | "اختلاف مصادر").
- اذكر وصف الخطأ بوضوح في \`issueDescription\`.
- اذكر التعديل المقترح في \`suggestedFix\`.
- اذكر الدليل العلمي أو اللغوي في \`evidence\`, والمصدر في \`source\` (لا تختلق رقم صفحة أو مرجعاً غير موجود؛ إذا لم يتوفر دليل كافٍ اكتب "تقدير لغوي/منهجي عام — يرجى التحقق من الكتاب المرجعي").
- حدد درجة الثقة في \`confidence\` ("عالية" | "متوسطة" | "تحتاج مراجعة").
- وضع النسخة المصححة الجاهزة للتطبيق الفوري في \`patchedPrompt\`, \`patchedCorrectAnswer\`, \`patchedOptions\`, \`patchedExplanation\`, أو \`patchedText\` (للنصوص والمذكرات).
إذا كان المحتوى سليماً تماماً اجعل \`overallStatus: "clean"\` و \`issues: []\`.

${contentBlock}`;

      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: prompt,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              overallStatus: { type: Type.STRING },
              scoreOutOf10: { type: Type.NUMBER },
              summary: { type: Type.STRING },
              issues: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    targetId: { type: Type.STRING },
                    targetLabel: { type: Type.STRING },
                    severity: { type: Type.STRING },
                    category: { type: Type.STRING },
                    issueDescription: { type: Type.STRING },
                    suggestedFix: { type: Type.STRING },
                    evidence: { type: Type.STRING },
                    source: { type: Type.STRING },
                    confidence: { type: Type.STRING },
                    patchedPrompt: { type: Type.STRING },
                    patchedCorrectAnswer: { type: Type.STRING },
                    patchedExplanation: { type: Type.STRING },
                    patchedOptions: { type: Type.ARRAY, items: { type: Type.STRING } },
                    patchedText: { type: Type.STRING },
                  },
                  required: ['targetId', 'targetLabel', 'severity', 'issueDescription', 'suggestedFix'],
                },
              },
            },
            required: ['overallStatus', 'scoreOutOf10', 'summary', 'issues'],
          },
        },
      });

      const parsed = JSON.parse(response.text || '{}') as {
        overallStatus?: string;
        scoreOutOf10?: number;
        summary?: string;
        issues?: Array<Record<string, unknown>>;
      };
      const verifiedAt = new Date().toISOString();
      const enrichedIssues = (parsed.issues || []).map((iss) => ({
        ...iss,
        verifiedAt,
      }));
      res.json({
        overallStatus: parsed.overallStatus === 'has_issues' || enrichedIssues.length > 0 ? 'has_issues' : 'clean',
        scoreOutOf10: Number(parsed.scoreOutOf10) || 10,
        summary: parsed.summary || 'تمت مراجعة المحتوى.',
        issues: enrichedIssues,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر تدقيق المحتوى: ${msg}` });
    }
  });

  // 4. Bulk Extract Questions from Past Exam / Book Text
  app.post('/api/ai/extract-questions-from-text', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'صلاحية المعلم مطلوبة.' });
        return;
      }
      const { rawText, grade, subject } = req.body as {
        rawText: string;
        grade?: string;
        subject?: string;
      };
      if (!rawText || rawText.trim().length < 20) {
        res.status(400).json({ error: 'النص المستخرج قصير جداً.' });
        return;
      }
      const ai = getGeminiClient();
      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `استخرج جميع الأسئلة الموجودة في نص الامتحان أو الكتاب الخارجي التالي ونظّم كل سؤال (النوع، نص السؤال، الخيارات إن وجدت، الإجابة النموذجية الصحيحة، الشرح المختصر، المهارة، الصعوبة easy/medium/hard، الدرس).
${grade ? `الصف: ${grade}` : ''} ${subject ? `المادة: ${subject}` : ''}

النص:
"""
${rawText.slice(0, 15000)}
"""`,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              questions: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    type: { type: Type.STRING },
                    prompt: { type: Type.STRING },
                    options: { type: Type.ARRAY, items: { type: Type.STRING } },
                    correctAnswer: { type: Type.STRING },
                    explanation: { type: Type.STRING },
                    difficulty: { type: Type.STRING },
                    skill: { type: Type.STRING },
                    lesson: { type: Type.STRING },
                    points: { type: Type.NUMBER },
                  },
                  required: ['type', 'prompt', 'correctAnswer'],
                },
              },
            },
            required: ['questions'],
          },
        },
      });
      const parsed = JSON.parse(response.text || '{}') as { questions?: Array<Partial<GeneratedQuestionItem>> };
      const list = (parsed.questions || []).map((q, idx) => ({
        id: `ext_${Date.now().toString(36)}_${idx}`,
        type: q.type || 'اختر الإجابة الصحيحة',
        prompt: q.prompt || '',
        options: Array.isArray(q.options) ? q.options : [],
        correctAnswer: q.correctAnswer || '',
        explanation: q.explanation || '',
        points: Number(q.points) || 1,
        difficulty: (q.difficulty === 'easy' || q.difficulty === 'hard' ? q.difficulty : 'medium') as 'easy' | 'medium' | 'hard',
        skill: q.skill || 'الفهم والاستيعاب',
        lesson: q.lesson || '',
      }));
      res.json({ questions: list });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر استخراج الأسئلة: ${msg}` });
    }
  });

  // 5. Camera / Image Paper Exam or Handwritten Homework Grader (Multimodal Vision)
  app.post('/api/ai/grade-paper-image', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'تصحيح الأوراق مخصص للمعلم فقط.' });
        return;
      }
      const { imageBase64, mimeType, answerKeySummary, maxScore, title } = req.body as {
        imageBase64: string;
        mimeType?: string;
        answerKeySummary?: string;
        maxScore?: number;
        title?: string;
      };
      if (!imageBase64) {
        res.status(400).json({ error: 'يرجى رفع صورة الورقة أولاً.' });
        return;
      }
      const cleanB64 = imageBase64.includes(',') ? imageBase64.split(',')[1] : imageBase64;
      const ai = getGeminiClient();
      const maxPts = Number(maxScore) || 10;

      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: {
          parts: [
            {
              inlineData: {
                mimeType: mimeType || 'image/jpeg',
                data: cleanB64,
              },
            },
            {
              text: `أنت مصحح خبير للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜.
اقرأ إجابات الطالب المكتوبة في هذه الورقة (${title || 'ورقة إجابة / واجب'}).
${answerKeySummary ? `نموذج الإجابة المرجعي:\n${answerKeySummary}\n` : ''}
قدّر الدرجة المقترحة من ${maxPts}، واكتب ملخصاً لما أجاب عنه الطالب بشكل صحيح وما أخطأ فيه مع نصيحة توجيهية قصيرة.`,
            },
          ],
        },
        config: {
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              detectedText: { type: Type.STRING },
              suggestedScore: { type: Type.NUMBER },
              feedback: { type: Type.STRING },
              itemNotes: { type: Type.ARRAY, items: { type: Type.STRING } },
            },
            required: ['detectedText', 'suggestedScore', 'feedback'],
          },
        },
      });

      const parsed = JSON.parse(response.text || '{}') as {
        detectedText?: string;
        suggestedScore?: number;
        feedback?: string;
        itemNotes?: string[];
      };
      res.json({
        detectedText: parsed.detectedText || '',
        suggestedScore: Math.min(maxPts, Math.max(0, Number(parsed.suggestedScore) || 0)),
        feedback: parsed.feedback || '',
        itemNotes: parsed.itemNotes || [],
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر تصحيح صورة الورقة: ${msg}` });
    }
  });

  // 6. Teacher Voice Transcription & Formatting
  app.post('/api/ai/transcribe-audio', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'هذه الأداة مخصصة للمعلم فقط.' });
        return;
      }
      const { audioBase64, mimeType } = req.body as { audioBase64: string; mimeType?: string };
      if (!audioBase64) {
        res.status(400).json({ error: 'لم يتم استلام ملف الصوت.' });
        return;
      }
      const cleanB64 = audioBase64.includes(',') ? audioBase64.split(',')[1] : audioBase64;
      const ai = getGeminiClient();
      const resp = await ai.models.generateContent({
        model: 'gemini-3.5-transcribe',
        contents: {
          parts: [
            { inlineData: { mimeType: mimeType || 'audio/webm', data: cleanB64 } },
            { text: 'فرّغ هذا التسجيل الصوتي باللغة العربية الفصحى المنسقة بدقة إملائية تامة.' },
          ],
        },
      });
      res.json({ text: resp.text || '' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر تفريغ التسجيل الصوتي: ${msg}` });
    }
  });

  // 7. AI Parent Follow-up Report Writer
  app.post('/api/ai/student-report-draft', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'صلاحية المعلم مطلوبة.' });
        return;
      }
      const { studentName, grade, attendanceStats, examSummary, notes } = req.body as {
        studentName: string;
        grade: string;
        attendanceStats: string;
        examSummary: string;
        notes?: string;
      };
      const ai = getGeminiClient();
      const resp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `اكتب رسالة تقرير متابعة تربوي احترافية ومختصرة لولي أمر الطالب/ة "${studentName}" (${grade}) باسم الأستاذ "𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜".
البيانات:
- الحضور والواجبات: ${attendanceStats}
- نتائج الامتحانات: ${examSummary}
- ملاحظات المعلم: ${notes || 'لا توجد ملاحظات إضافية'}

اجعل النبرة مشجعة وموضوعية وتتضمن: (1) نقاط القوة، (2) ما يحتاج تركيزاً، (3) خطة الأسبوع القادم.`,
      });
      res.json({ report: resp.text || '' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر صياغة التقرير: ${msg}` });
    }
  });

  // 7b. Smart Cross-Exam Revision Plan & Cumulative Test Generator
  app.post('/api/ai/smart-revision-plan', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { studentName, subject, grade, wrongQuestions, questionCount } = req.body as {
        studentName?: string;
        subject?: string;
        grade?: string;
        wrongQuestions: Array<{
          examTitle?: string;
          prompt: string;
          studentAnswer?: string;
          correctAnswer?: string;
          lesson?: string;
          skill?: string;
          type?: string;
        }>;
        questionCount?: number;
      };
      if (!Array.isArray(wrongQuestions) || wrongQuestions.length === 0) {
        res.status(400).json({ error: 'لا توجد أسئلة خاطئة مجمّعة لبناء خطة المراجعة.' });
        return;
      }
      const qCount = Math.min(20, Math.max(4, Number(questionCount) || Math.min(12, Math.max(6, wrongQuestions.length + 2))));
      const ai = getGeminiClient();
      const summaryLines = wrongQuestions
        .slice(0, 35)
        .map(
          (w, i) =>
            `${i + 1}. [الامتحان: ${w.examTitle || 'عام'} | الدرس: ${w.lesson || 'غير محدد'} | المهارة: ${
              w.skill || 'الفهم'
            }]\nالسؤال: ${w.prompt}\nإجابة الطالب الخاطئة: ${w.studentAnswer || '—'} | الصواب: ${w.correctAnswer || '—'}`
        )
        .join('\n\n');

      const resp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `أنت خبير تشخيص تربوي وبناء خطط علاجية للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜.
حلل جميع الأخطاء التالية التي وقع فيها الطالب/ة "${studentName || 'الطالب'}" في مادة "${subject || 'المنهج المصري'}" (${
          grade || 'عام'
        }) عبر امتحانات متعددة، ثم:
1. قدّم تشخيصاً دقيقاً (diagnosis) لنقاط الضعف المتكررة والأنماط المسببة للخطأ.
2. صمّم خطة مراجعة متدرجة (revisionSteps) من 3 إلى 5 خطوات مركزة لمعالجة هذه الثغرات مع نصيحة تطبيقية في كل خطوة.
3. اكتب نصيحة إتقان ختامية (masteryAdvice).
4. أنشئ اختباراً تجميعياً مخصصاً من ${qCount} سؤال جديد ومشابه لأفكار الأخطاء (مع تنويع الأسئلة الموضوعية: اختر الإجابة الصحيحة، صح وخطأ، أكمل) لقياس تحسن الطالب وتثبيت المعلومة، مع تحديد الإجابة الصحيحة والشرح التربوي والدرس والمهارة لكل سؤال.

سجل الأخطاء المتجمعة:
${summaryLines}`,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              examTitle: { type: Type.STRING },
              diagnosis: { type: Type.STRING },
              revisionSteps: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    stepNumber: { type: Type.NUMBER },
                    focusTopic: { type: Type.STRING },
                    explanation: { type: Type.STRING },
                    practiceTip: { type: Type.STRING },
                  },
                  required: ['stepNumber', 'focusTopic', 'explanation', 'practiceTip'],
                },
              },
              masteryAdvice: { type: Type.STRING },
              questions: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    type: { type: Type.STRING },
                    prompt: { type: Type.STRING },
                    options: { type: Type.ARRAY, items: { type: Type.STRING } },
                    correctAnswer: { type: Type.STRING },
                    explanation: { type: Type.STRING },
                    difficulty: { type: Type.STRING },
                    skill: { type: Type.STRING },
                    lesson: { type: Type.STRING },
                    points: { type: Type.NUMBER },
                  },
                  required: ['type', 'prompt', 'correctAnswer', 'explanation'],
                },
              },
            },
            required: ['examTitle', 'diagnosis', 'revisionSteps', 'masteryAdvice', 'questions'],
          },
        },
      });

      const parsed = JSON.parse((resp.text || '{}').trim()) as {
        examTitle?: string;
        diagnosis?: string;
        revisionSteps?: Array<{ stepNumber: number; focusTopic: string; explanation: string; practiceTip: string }>;
        masteryAdvice?: string;
        questions?: Array<Partial<GeneratedQuestionItem>>;
      };

      const mappedQuestions = (parsed.questions || []).map((q, idx) => ({
        id: `rev_${Date.now().toString(36)}_${idx}`,
        type: q.type || 'اختر الإجابة الصحيحة',
        prompt: q.prompt || '',
        options: Array.isArray(q.options) ? q.options : [],
        correctAnswer: q.correctAnswer || '',
        explanation: q.explanation || '',
        points: Number(q.points) || 1,
        difficulty: (q.difficulty === 'easy' || q.difficulty === 'hard' ? q.difficulty : 'medium') as 'easy' | 'medium' | 'hard',
        skill: q.skill || 'معالجة الأخطاء الشائعة',
        lesson: q.lesson || 'مراجعة تجميعية',
      }));

      res.json({
        examTitle: parsed.examTitle || `الاختبار التجميعي الذكي — ${studentName || subject || 'مراجعة شاملة'}`,
        diagnosis: parsed.diagnosis || 'تم تحليل الأخطاء المتكررة وبناء الخطة المناسبة.',
        revisionSteps: parsed.revisionSteps || [],
        masteryAdvice: parsed.masteryAdvice || 'راجع أخطاءك بهدوء قبل حل الاختبار التجميعي.',
        questions: mappedQuestions,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg === 'GEMINI_API_KEY_MISSING') {
        res.status(503).json({ error: 'خدمة التوليد الذكي غير مفعلة حالياً.' });
        return;
      }
      res.status(500).json({ error: `تعذر بناء خطة المراجعة الذكية: ${msg}` });
    }
  });

  // 7c. Arabic Language Lab (Full Tashkeel, I'rab Table, Estekhrag, Nahw Exam Questions)
  app.post('/api/ai/arabic-lab', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'مختبر اللغة العربية مخصص للمعلم فقط.' });
        return;
      }
      const { paragraph, grade, questionCount } = req.body as {
        paragraph: string;
        grade?: string;
        questionCount?: number;
      };
      if (!paragraph || paragraph.trim().length < 15) {
        res.status(400).json({ error: 'يرجى إدخال فقرة نحوية مناسبة (15 حرفاً على الأقل).' });
        return;
      }
      const qCount = Math.min(12, Math.max(3, Number(questionCount) || 5));
      const ai = getGeminiClient();
      const resp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `أنت أستاذ خبير في النحو والإعراب والبلاغة بالمنهج المصري للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜.
حلل الفقرة التالية المناسبة للصف "${grade || 'المرحلة الإعدادية والثانوية'}" بدقة نحوية كاملة:
1. أعد كتابة الفقرة مضبوطة بالشكل الكامل (التشكيل الكامل الصحيح لجميع الحروف وأواخر الكلمات) في vocalizedText.
2. استخرج أهم 6 إلى 10 كلمات محورية وأعربها إعراباً تفصيلياً نموذجياً في irabWords.
3. استخرج أبرز الظواهر النحوية المناسبة للمنهج (مثل: فعل معرب/مبني، اسم معرب/مبني، نعت، حال، توكيد، مفعول لأجله، خبر، اسم فاعل/مفعول...) في estekhrag.
4. أنشئ ${qCount} سؤالاً نحوياً متنوعاً (إعراب، استخراج، صوّب الخطأ، اختر الإجابة الصحيحة) في questions مع الإجابة والشرح.

الفقرة:
"""
${paragraph.trim().slice(0, 4000)}
"""`,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              vocalizedText: { type: Type.STRING },
              irabWords: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    word: { type: Type.STRING },
                    irab: { type: Type.STRING },
                  },
                  required: ['word', 'irab'],
                },
              },
              estekhrag: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    category: { type: Type.STRING },
                    extracted: { type: Type.STRING },
                    explanation: { type: Type.STRING },
                  },
                  required: ['category', 'extracted', 'explanation'],
                },
              },
              questions: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    type: { type: Type.STRING },
                    prompt: { type: Type.STRING },
                    options: { type: Type.ARRAY, items: { type: Type.STRING } },
                    correctAnswer: { type: Type.STRING },
                    explanation: { type: Type.STRING },
                    difficulty: { type: Type.STRING },
                    skill: { type: Type.STRING },
                    points: { type: Type.NUMBER },
                  },
                  required: ['type', 'prompt', 'correctAnswer', 'explanation'],
                },
              },
            },
            required: ['vocalizedText', 'irabWords', 'estekhrag', 'questions'],
          },
        },
      });
      const parsed = JSON.parse((resp.text || '{}').trim()) as {
        vocalizedText?: string;
        irabWords?: Array<{ word: string; irab: string }>;
        estekhrag?: Array<{ category: string; extracted: string; explanation: string }>;
        questions?: Array<Partial<GeneratedQuestionItem>>;
      };
      res.json({
        vocalizedText: parsed.vocalizedText || paragraph,
        irabWords: parsed.irabWords || [],
        estekhrag: parsed.estekhrag || [],
        questions: (parsed.questions || []).map((q, idx) => ({
          id: `arab_${Date.now().toString(36)}_${idx}`,
          type: q.type || 'اختر الإجابة الصحيحة',
          prompt: q.prompt || '',
          options: Array.isArray(q.options) ? q.options : [],
          correctAnswer: q.correctAnswer || '',
          explanation: q.explanation || '',
          points: Number(q.points) || 1,
          difficulty: (q.difficulty === 'easy' || q.difficulty === 'hard' ? q.difficulty : 'medium') as 'easy' | 'medium' | 'hard',
          skill: q.skill || 'النحو والإعراب',
          lesson: 'تطبيق نحوي',
        })),
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر تحليل الفقرة النحوية: ${msg}` });
    }
  });

  // 7d. AI Draft Reply for Ask the Teacher Inbox
  app.post('/api/ai/answer-student-question', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'تجهيز الردود مخصص للمعلم فقط.' });
        return;
      }
      const { subject, grade, lesson, questionText } = req.body as {
        subject?: string;
        grade?: string;
        lesson?: string;
        questionText: string;
      };
      if (!questionText || questionText.trim().length < 3) {
        res.status(400).json({ error: 'نص السؤال مطلوب.' });
        return;
      }
      const ai = getGeminiClient();
      const resp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `أنت معلم خبير مساعد للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜 (${subject || 'المنهج المصري'} — ${grade || ''}${
          lesson ? ` — ${lesson}` : ''
        }).
أرسل طالب السؤال التالي:
"${questionText.trim()}"

قم بصياغة:
1. إجابة تربوية واضحة ومبسطة ومباشرة للطالب (clearAnswer).
2. قاعدة ذهبية أو ملخص سريع في سطر واحد (keyPoint).
3. سؤال تدريبي اختياري من متعدد (practiceQuestion) يمكن للأستاذ إضافته مباشرة لبنك الأسئلة بناءً على استفسار الطالب.`,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              clearAnswer: { type: Type.STRING },
              keyPoint: { type: Type.STRING },
              practiceQuestion: {
                type: Type.OBJECT,
                properties: {
                  prompt: { type: Type.STRING },
                  options: { type: Type.ARRAY, items: { type: Type.STRING } },
                  correctAnswer: { type: Type.STRING },
                  explanation: { type: Type.STRING },
                },
                required: ['prompt', 'options', 'correctAnswer', 'explanation'],
              },
            },
            required: ['clearAnswer', 'keyPoint', 'practiceQuestion'],
          },
        },
      });
      const parsed = JSON.parse((resp.text || '{}').trim());
      res.json(parsed);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر صياغة الرد الذكي: ${msg}` });
    }
  });

  // 8. Student Portal "Explain Why" Tutor (constrained to question + teacher explanation/snippet)
  app.post('/api/ai/student-explain-mistake', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { prompt: qPrompt, studentAnswer, correctAnswer, explanation, subject, grade } = req.body as {
        prompt: string;
        studentAnswer?: string;
        correctAnswer?: string;
        explanation?: string;
        subject?: string;
        grade?: string;
      };
      if (!qPrompt) {
        res.status(400).json({ error: 'بيانات السؤال مطلوبة.' });
        return;
      }
      const ai = getGeminiClient();
      const resp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `أنت معلم مساعد لطالب في ${grade || 'المرحلة الدراسية'} بمادة ${subject || 'المنهج الدراسي'} في منصة الأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜.
اشرح للطالب بأسلوب تربوي مبسط ومشجع سبب صحة الإجابة النموذجية لهذا السؤال الذي أنهاه بالفعل:
السؤال: ${qPrompt}
إجابة الطالب: ${studentAnswer || 'لم يجب'}
الإجابة الصحيحة: ${correctAnswer || 'غير محددة'}
ملحوظة المعلم: ${explanation || 'لا توجد'}

قدم الشرح في 3-4 أسطر واضحة ومباشرة دون إطالة.`,
      });
      res.json({ explanationText: resp.text || '' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `تعذر توليد الشرح المبسط: ${msg}` });
    }
  });

  // ============================================================================
  // Teacher Private Educational Diploma Hub (الدبلومة التربوية وتطوير المعلم)
  // ============================================================================
  app.post('/api/diploma/focus-points', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const allowedDiploma = await verifyDiplomaAccessViaFirestore(token, req.authUser!);
      if (!allowedDiploma) {
        res.status(403).json({ error: 'قسم الدبلومة التربوية مخصص للمعلم الرئيسي وزملاء الدبلومة المصرّح لهم فقط.' });
        return;
      }

      const {
        mode = 'lesson_focus',
        courseName = 'أساسيات التربوي',
        bookName = '',
        lessonName = '',
        sourceText = '',
        customQuestion = '',
      } = req.body as {
        mode?: 'lesson_focus' | 'pre_diploma_essentials' | 'book_lookup';
        courseName?: string;
        bookName?: string;
        lessonName?: string;
        sourceText?: string;
        customQuestion?: string;
      };

      const cleanText = String(sourceText || '').trim().slice(0, 60000);
      if (!cleanText && !bookName.trim() && !lessonName.trim() && !customQuestion.trim()) {
        res.status(400).json({ error: 'يرجى كتابة اسم الكتاب/الدرس أو رفع نص المحاضرة لاستخراج نقط التركيز.' });
        return;
      }

      const ai = getGeminiClient();
      let groundedNotes = '';
      let citations: Array<{ title: string; uri: string }> = [];

      // When the teacher gives a book/topic name without full text (or asks for pre-diploma readiness),
      // gather accurate Educational Diploma references with Google Search grounding first.
      if (cleanText.length < 150 || mode === 'pre_diploma_essentials' || mode === 'book_lookup') {
        try {
          const searchPrompt =
            mode === 'pre_diploma_essentials'
              ? `ابحث بدقة في مقررات الدبلومة العامة في التربية بالجامعات المصرية عن أهم المعلومات التأسيسية والمفاهيم المحورية التي يجب أن يعرفها المعلم قبل دخول الدبلومة التربوية في مقرر "${courseName}".
${bookName ? `الكتاب أو المرجع: ${bookName}` : ''}
${customQuestion ? `تركيز خاص من المعلم: ${customQuestion}` : ''}
${cleanText ? `مادة مرفقة من المعلم:\n${cleanText.slice(0, 8000)}` : ''}
قدّم حقائق تربوية دقيقة ومحددة تصلح كمرجع مذاكرة وامتحانات بابل شيت.`
              : `ابحث في مقررات الدبلومة العامة في التربية (مصر) عن أهم النقاط الأساسية والفخاخ الامتحانية في:
المقرر: ${courseName}
الكتاب: ${bookName || courseName}
الدرس / الفصل: ${lessonName || 'عام'}
${customQuestion ? `سؤال المعلم: ${customQuestion}` : ''}
${cleanText ? `نص مرفق:\n${cleanText.slice(0, 8000)}` : ''}`;

          const searchResp = await ai.models.generateContent({
            model: 'gemini-4-hydrogen',
            contents: searchPrompt,
            config: {
              tools: [{ googleSearch: {} }],
            },
          });
          groundedNotes = (searchResp.text || '').trim();
          const rawChunks = searchResp.candidates?.[0]?.groundingMetadata?.groundingChunks || [];
          citations = rawChunks
            .map((ch) => (ch as { web?: { uri?: string; title?: string } }).web)
            .filter((w): w is { uri: string; title?: string } => Boolean(w?.uri))
            .slice(0, 8)
            .map((w) => ({
              title: w.title || w.uri,
              uri: w.uri,
            }));
        } catch (searchErr) {
          console.warn('Diploma grounded search fallback:', searchErr);
        }
      }

      const structuringPrompt = `أنت مستشار أكاديمي وخبير امتحانات "الدبلومة العامة في التربية" (الجامعات المصرية) لمساعدة الأستاذ "𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜" على التفوق في دراسته التربوية.
المطلوب: استخراج **أهم النقط الأساسية والتركيزات الامتحانية عالية الأهمية** (High-Yield Exam Focus Points) بصياغة واضحة ومكثفة تصلح للمراجعة السريعة ولأسئلة البابل شيت (MCQ).

بيانات الدراسة:
- المقرر: ${courseName}
- اسم الكتاب / المذكرة: ${bookName || courseName}
- الدرس / الفصل: ${lessonName || 'مراجعة شاملة'}
- الوضع المطلوب: ${
        mode === 'pre_diploma_essentials'
          ? 'تأهيل وتأسيس قبل دخول الدبلومة التربوية + أهم المعلومات الأساسية'
          : 'تلخيص أهم النقط الأساسية والتركيزات موضع الامتحان'
      }
${customQuestion ? `- طلب خاص من المعلم: ${customQuestion}` : ''}

${cleanText ? `النص المرفق من المعلم:\n"""\n${cleanText}\n"""` : ''}
${groundedNotes ? `\nمعلومات مرجعية تربوية إضافية:\n"""\n${groundedNotes.slice(0, 20000)}\n"""` : ''}

التعليمات الصارمة:
1. ضع خلاصة مركزة (3-5 جمل) في summary.
2. استخرج من 6 إلى 10 نقاط تركيز أساسية في focusPoints: لكل نقطة title قصير واضح، وdetail محدد (تعريف/عالم/تصنيف/مراحل/شروط)، وexamTrap يوضح كيف يوقع واضع الامتحان الممتحن في سؤال MCQ (مثل الخلط بين مفهومين أو اسم العالم أو الترتيب)، وimportance ('critical' أو 'high' أو 'medium').
3. استخرج 5 إلى 7 معلومات تأسيسية لا غنى عنها قبل دخول الدبلومة أو المحاضرة في preDiplomaEssentials.
4. استخرج 3 إلى 5 مقارنات سريعة (مفهوم أ vs مفهوم ب والفرق الجوهري بينهما) في comparisons لأنها من أشهر أسئلة الاختيار من متعدد في التربوي.`;

      const structuredResp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: structuringPrompt,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              summary: { type: Type.STRING },
              focusPoints: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    title: { type: Type.STRING },
                    detail: { type: Type.STRING },
                    examTrap: { type: Type.STRING },
                    importance: { type: Type.STRING },
                  },
                  required: ['title', 'detail', 'examTrap', 'importance'],
                },
              },
              preDiplomaEssentials: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
              comparisons: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    conceptA: { type: Type.STRING },
                    conceptB: { type: Type.STRING },
                    difference: { type: Type.STRING },
                  },
                  required: ['conceptA', 'conceptB', 'difference'],
                },
              },
            },
            required: ['summary', 'focusPoints', 'preDiplomaEssentials', 'comparisons'],
          },
        },
      });

      const parsed = JSON.parse((structuredResp.text || '{}').trim()) as {
        summary?: string;
        focusPoints?: Array<{ title: string; detail: string; examTrap?: string; importance?: string }>;
        preDiplomaEssentials?: string[];
        comparisons?: Array<{ conceptA: string; conceptB: string; difference: string }>;
      };

      const focusPoints = (parsed.focusPoints || []).map((fp, idx) => ({
        id: `fp_${Date.now()}_${idx}`,
        title: String(fp.title || '').trim(),
        detail: String(fp.detail || '').trim(),
        examTrap: String(fp.examTrap || '').trim(),
        importance: (fp.importance === 'critical' || fp.importance === 'medium' ? fp.importance : 'high') as
          | 'critical'
          | 'high'
          | 'medium',
        pinned: fp.importance === 'critical',
      }));

      res.json({
        summary: String(parsed.summary || '').trim(),
        focusPoints,
        preDiplomaEssentials: (parsed.preDiplomaEssentials || []).map((s) => String(s).trim()).filter(Boolean),
        comparisons: (parsed.comparisons || []).filter((c) => c.conceptA && c.conceptB && c.difference),
        citations,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('Diploma focus-points error:', err);
      if (msg === 'GEMINI_API_KEY_MISSING') {
        res.status(503).json({ error: 'مفتاح Gemini API غير مضاف في لوحة الأسرار (Settings > Secrets).' });
        return;
      }
      res.status(500).json({ error: `تعذر استخراج نقط التركيز للدبلومة: ${msg}` });
    }
  });

  app.post('/api/diploma/generate-mcq-exam', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const allowedDiploma = await verifyDiplomaAccessViaFirestore(token, req.authUser!);
      if (!allowedDiploma) {
        res.status(403).json({ error: 'توليد امتحانات الدبلومة مخصص للمعلم الرئيسي وزملاء الدبلومة المصرّح لهم فقط.' });
        return;
      }

      const {
        title = 'امتحان تدريبي - الدبلومة التربوية',
        courseName = 'أصول التربية',
        bookName = '',
        lessonName = '',
        sourceText = '',
        questionCount = 15,
        mode = 'standard',
        dueMistakes = [],
      } = req.body as {
        title?: string;
        courseName?: string;
        bookName?: string;
        lessonName?: string;
        sourceText?: string;
        questionCount?: number;
        mode?: 'standard' | 'mistakes_drill' | 'pre_diploma';
        dueMistakes?: Array<{
          id: string;
          prompt: string;
          options: string[];
          correctIndex: number;
          correctAnswer: string;
          explanation: string;
          focusTip: string;
          courseName?: string;
          bookName?: string;
          lessonName?: string;
        }>;
      };

      const targetCount = Math.min(50, Math.max(3, Number(questionCount) || 15));
      const cleanMistakes = Array.isArray(dueMistakes)
        ? dueMistakes.filter((m) => m.prompt && Array.isArray(m.options) && m.options.length === 4)
        : [];

      const mistakeQuota =
        mode === 'mistakes_drill'
          ? Math.min(cleanMistakes.length, targetCount)
          : Math.min(cleanMistakes.length, Math.max(0, Math.floor(targetCount * 0.35)));

      const selectedMistakeQuestions = cleanMistakes.slice(0, mistakeQuota).map((m, idx) => ({
        id: `dq_m_${Date.now()}_${idx}`,
        prompt: m.prompt,
        options: m.options.slice(0, 4),
        correctIndex: Math.min(3, Math.max(0, Number(m.correctIndex) || 0)),
        correctAnswer: m.correctAnswer,
        explanation: m.explanation || 'سؤال متكرر من أخطائك السابقة لتثبيت المعلومة.',
        focusTip: m.focusTip || `تذكّر: ${m.correctAnswer}`,
        courseName: m.courseName || courseName,
        bookName: m.bookName || bookName,
        lessonName: m.lessonName || lessonName,
        fromMistakeId: m.id,
      }));

      const freshNeeded = Math.max(0, targetCount - selectedMistakeQuestions.length);
      const freshQuestions: Array<{
        id: string;
        prompt: string;
        options: string[];
        correctIndex: number;
        correctAnswer: string;
        explanation: string;
        focusTip: string;
        courseName: string;
        bookName: string;
        lessonName: string;
      }> = [];

      if (freshNeeded > 0) {
        const ai = getGeminiClient();
        const trimmedSource = String(sourceText || '').trim().slice(0, 60000);
        const mistakePromptsHint =
          selectedMistakeQuestions.length > 0
            ? `\nتجنب تكرار هذه الأسئلة الموجودة بالفعل:\n${selectedMistakeQuestions.map((q) => `- ${q.prompt}`).join('\n')}`
            : '';

        const prompt = `أنت واضع امتحانات "بابل شيت (اختيار من متعدد فقط)" محترف لطلاب الدبلومة العامة في التربية بالجامعات المصرية.
أنشئ ${freshNeeded} سؤالاً من نوع "اختر الإجابة الصحيحة (4 اختيارات فقط أ / ب / ج / د)" للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜.

البيانات:
- عنوان الامتحان: ${title}
- المقرر: ${courseName}
- الكتاب: ${bookName || courseName}
- الدرس / الفصل: ${lessonName || 'شامل'}
- نوع التدريب: ${
          mode === 'pre_diploma'
            ? 'أساسيات ومفاهيم لا غنى عنها قبل دخول الدبلومة التربوية'
            : mode === 'mistakes_drill'
            ? 'أسئلة تعزيز وتثبيت مفاهيم شبيهة بالأخطاء السابقة'
            : 'امتحان بابل شيت يحاكي امتحانات كليات التربية'
        }
${mistakePromptsHint}

المحتوى المرجعي:
"""
${trimmedSource || `مقرر الدبلومة العامة في التربية: ${courseName} - ${bookName} - ${lessonName}`}
"""

قواعد إلزامية:
1. كل سؤال يجب أن يحتوي على 4 اختيارات بالضبط في options (بدون كتابة حروف أ/ب/ج/د داخل النص نفسه).
2. ضع رقم الإجابة الصحيحة (0 أو 1 أو 2 أو 3) في correctIndex، والنص الدقيق لها في correctAnswer.
3. ركز على الفهم والتمييز بين النظريات والعلماء والمصطلحات والتطبيقات التربوية (مستوى امتحانات البابل شيت الفعلية).
4. اكتب explanation واضحاً، وfocusTip من سطر واحد ("قاعدة ذهبية للتثبيت") ليبقى أمام عين المعلم إذا أخطأ.`;

        const resp = await ai.models.generateContent({
          model: 'gemini-4-hydrogen',
          contents: prompt,
          config: {
            thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
            responseMimeType: 'application/json',
            responseSchema: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  prompt: { type: Type.STRING },
                  options: { type: Type.ARRAY, items: { type: Type.STRING } },
                  correctIndex: { type: Type.INTEGER },
                  correctAnswer: { type: Type.STRING },
                  explanation: { type: Type.STRING },
                  focusTip: { type: Type.STRING },
                },
                required: ['prompt', 'options', 'correctIndex', 'correctAnswer', 'explanation', 'focusTip'],
              },
            },
          },
        });

        const parsed = JSON.parse((resp.text || '[]').trim()) as Array<{
          prompt: string;
          options: string[];
          correctIndex: number;
          correctAnswer: string;
          explanation: string;
          focusTip: string;
        }>;

        for (let i = 0; i < parsed.length; i++) {
          const item = parsed[i];
          const opts = Array.isArray(item.options) ? item.options.map((o) => String(o).trim()).filter(Boolean) : [];
          if (!item.prompt || opts.length < 4) continue;
          const cleanOpts = opts.slice(0, 4);
          let cIdx = Number(item.correctIndex);
          if (!Number.isInteger(cIdx) || cIdx < 0 || cIdx > 3) {
            const foundIdx = cleanOpts.findIndex(
              (o) => normalizeArabicText(o) === normalizeArabicText(item.correctAnswer || '')
            );
            cIdx = foundIdx >= 0 ? foundIdx : 0;
          }
          freshQuestions.push({
            id: `dq_${Date.now()}_${i}_${Math.random().toString(36).slice(2, 5)}`,
            prompt: item.prompt.trim(),
            options: cleanOpts,
            correctIndex: cIdx,
            correctAnswer: cleanOpts[cIdx],
            explanation: (item.explanation || '').trim(),
            focusTip: (item.focusTip || `تذكر أن الإجابة الصحيحة هي: ${cleanOpts[cIdx]}`).trim(),
            courseName,
            bookName,
            lessonName,
          });
          if (freshQuestions.length >= freshNeeded) break;
        }
      }

      const combined = [...selectedMistakeQuestions, ...freshQuestions];
      res.json({
        questions: combined,
        includesMistakesCount: selectedMistakeQuestions.length,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('Diploma generate-mcq-exam error:', err);
      if (msg === 'GEMINI_API_KEY_MISSING') {
        res.status(503).json({ error: 'مفتاح Gemini API غير مضاف في لوحة الأسرار (Settings > Secrets).' });
        return;
      }
      res.status(500).json({ error: `تعذر توليد امتحان البابل شيت: ${msg}` });
    }
  });

  app.post('/api/diploma/reinforce-mistake', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const allowedDiploma = await verifyDiplomaAccessViaFirestore(token, req.authUser!);
      if (!allowedDiploma) {
        res.status(403).json({ error: 'تثبيت الأخطاء مخصص للمعلم الرئيسي وزملاء الدبلومة المصرّح لهم فقط.' });
        return;
      }
      const { prompt: qPrompt, correctAnswer, chosenAnswer, courseName, bookName, lessonName, explanation } = req.body as {
        prompt: string;
        correctAnswer: string;
        chosenAnswer?: string;
        courseName?: string;
        bookName?: string;
        lessonName?: string;
        explanation?: string;
      };
      if (!qPrompt || !correctAnswer) {
        res.status(400).json({ error: 'بيانات السؤال مطلوبة.' });
        return;
      }

      const ai = getGeminiClient();
      const resp = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `أنت مدرب ذاكرة تربوي للأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜 في الدبلومة التربوية.
المعلم أخطأ في هذا السؤال ونريد تثبيت المعلومة في ذهنه للأبد حتى لا يقع فيها ثانية:
- المقرر/الكتاب: ${courseName || ''} ${bookName ? `(${bookName})` : ''} ${lessonName ? `- ${lessonName}` : ''}
- السؤال: ${qPrompt}
- الاختيار الخاطئ الذي اختاره: ${chosenAnswer || 'غير محدد'}
- الإجابة الصحيحة: ${correctAnswer}
- التفسير الأولي: ${explanation || 'لا يوجد'}

اكتب في 3 نقاط قصيرة ومباشرة بالعربية:
1. لماذا يوقع هذا السؤال في الخطأ؟ (الفرق بين اختياره والإجابة الصحيحة).
2. المعلومة المؤكدة التي يجب حفظها بوضوح.
3. رابط ذهني / علامة سريعة تذكّره بالإجابة الصحيحة فوراً في امتحان البابل شيت.`,
      });

      res.json({
        reinforcementNote: (resp.text || '').trim(),
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg === 'GEMINI_API_KEY_MISSING') {
        res.status(503).json({ error: 'مفتاح Gemini API غير مضاف في لوحة الأسرار (Settings > Secrets).' });
        return;
      }
      res.status(500).json({ error: `تعذر توليد ملاحظة التثبيت: ${msg}` });
    }
  });

  // Seal answer keys server-side (AES-256-GCM) so students cannot read answers from Firestore
  app.post('/api/exams/seal-key', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'صلاحية المدرس مطلوبة.' });
        return;
      }
      const { examId, answers } = req.body as {
        examId: string;
        answers: SealedAnswerEntry[];
      };
      if (!examId || !Array.isArray(answers)) {
        res.status(400).json({ error: 'بيانات نموذج الإجابة غير مكتملة.' });
        return;
      }
      const sealedKey = sealData({ examId, answers });
      res.json({ sealedKey });
    } catch (err) {
      console.error('Seal key error:', err);
      res.status(500).json({ error: 'فشل تشفير نموذج الإجابة.' });
    }
  });

  // Server-side exam submission grading & timing verification + rich item breakdown
  app.post('/api/exams/grade-submission', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const {
        examId,
        attemptId,
        studentId,
        sealedKey,
        answers,
        serverStartedMs,
        durationMinutes,
        endAt,
        showAnswersToStudents,
      } = req.body as {
        examId: string;
        attemptId: string;
        studentId: string;
        sealedKey: string;
        answers: Record<string, string>;
        serverStartedMs: number;
        durationMinutes: number;
        endAt?: string;
        showAnswersToStudents?: boolean;
      };

      if (!examId || !attemptId || !sealedKey) {
        res.status(400).json({ error: 'بيانات تسليم الامتحان غير مكتملة.' });
        return;
      }

      const nowMs = Date.now();
      const allowedWindowMs = (Number(durationMinutes) || 30) * 60 * 1000 + 60 * 1000;
      const timedOut = serverStartedMs > 0 && nowMs - serverStartedMs > allowedWindowMs;
      const pastEndDate = endAt ? nowMs > new Date(endAt).getTime() + 60 * 1000 : false;

      const unsealed = unsealData<{
        examId: string;
        answers: SealedAnswerEntry[];
      }>(sealedKey);

      if (unsealed.examId !== examId) {
        res.status(400).json({ error: 'نموذج الإجابة لا يطابق هذا الامتحان.' });
        return;
      }

      let objectiveScore = 0;
      let maxObjectiveScore = 0;
      let hasEssayQuestions = false;
      const breakdown: Array<{
        questionId: string;
        prompt?: string;
        type?: string;
        skill?: string;
        lesson?: string;
        unit?: string;
        difficulty?: 'easy' | 'medium' | 'hard';
        isObjective: boolean;
        isCorrect: boolean | null;
        earnedPoints: number;
        maxPoints: number;
        studentAnswer?: string;
        correctAnswer?: string;
        explanation?: string;
      }> = [];

      for (const item of unsealed.answers) {
        const pts = Number(item.points) || 1;
        const studentAns = (answers && answers[item.id]) || '';
        const isObj = OBJECTIVE_TYPES.has(item.type);

        if (isObj) {
          maxObjectiveScore += pts;
          const isCorrect =
            studentAns.trim().length > 0 &&
            normalizeArabicText(studentAns) === normalizeArabicText(item.correctAnswer);
          const earned = isCorrect ? pts : 0;
          objectiveScore += earned;
          breakdown.push({
            questionId: item.id,
            prompt: item.prompt,
            type: item.type,
            skill: item.skill || 'الفهم والاستيعاب',
            lesson: item.lesson || '',
            unit: item.unit || '',
            difficulty: item.difficulty || 'medium',
            isObjective: true,
            isCorrect,
            earnedPoints: earned,
            maxPoints: pts,
            studentAnswer: studentAns,
            ...(showAnswersToStudents
              ? { correctAnswer: item.correctAnswer, explanation: item.explanation }
              : {}),
          });
        } else {
          hasEssayQuestions = true;
          breakdown.push({
            questionId: item.id,
            prompt: item.prompt,
            type: item.type,
            skill: item.skill || 'التفسير والسببية',
            lesson: item.lesson || '',
            unit: item.unit || '',
            difficulty: item.difficulty || 'medium',
            isObjective: false,
            isCorrect: null,
            earnedPoints: 0,
            maxPoints: pts,
            studentAnswer: studentAns,
            ...(showAnswersToStudents
              ? { correctAnswer: item.correctAnswer, explanation: item.explanation }
              : {}),
          });
        }
      }

      const gradingReceipt = signReceipt({
        attemptId,
        examId,
        studentId,
        studentUid: req.authUser!.uid,
        objectiveScore: Number(objectiveScore.toFixed(2)),
        maxObjectiveScore: Number(maxObjectiveScore.toFixed(2)),
        gradedAtMs: nowMs,
      });

      res.json({
        objectiveScore: Number(objectiveScore.toFixed(2)),
        maxObjectiveScore: Number(maxObjectiveScore.toFixed(2)),
        hasEssayQuestions,
        timedOut,
        pastEndDate,
        submittedAt: new Date(nowMs).toISOString(),
        gradingReceipt,
        breakdown,
      });
    } catch (err) {
      console.error('Grade submission error:', err);
      res.status(500).json({ error: 'حدث خطأ أثناء التصحيح التلقائي على الخادم.' });
    }
  });

  app.post('/api/exams/verify-receipt', verifyFirebaseBearer, (req: AuthenticatedRequest, res: Response) => {
    const { gradingReceipt } = req.body as { gradingReceipt: string };
    res.json(verifyReceiptSignature(gradingReceipt));
  });

  // Export A4 RTL Arabic Word (.docx) Exam or Answer Key honoring Paper Design Studio config
  app.post('/api/exams/export-docx', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const token = req.headers.authorization!.slice(7).trim();
      const isAllowedTeacher = await verifyTeacherViaFirestore(token, req.authUser!);
      if (!isAllowedTeacher) {
        res.status(403).json({ error: 'تصدير ملفات Word مخصص للمدرس فقط.' });
        return;
      }

      const { exam, includeAnswers, variantLabel, paperDesign } = req.body as {
        exam: {
          title: string;
          subject: string;
          grade: string;
          system: string;
          durationMinutes: number;
          totalMarks: number;
          instructions?: string;
          questions: Array<{
            type: string;
            prompt: string;
            options?: string[];
            correctAnswer?: string;
            explanation?: string;
            points: number;
          }>;
        };
        includeAnswers?: boolean;
        variantLabel?: string;
        paperDesign?: {
          templateStyle?:
            | 'classic'
            | 'compact'
            | 'bubble_sheet'
            | 'luxury_navy_gold'
            | 'final_revision'
            | 'oral_exam';
          fontSize?: number;
          questionSpacing?: number;
          marginMm?: number;
          logoFirstPageOnly?: boolean;
          showStudentBox?: boolean;
          showBubbleGrid?: boolean;
          customHeaderNote?: string;
        };
      };

      const marginMm = Math.min(24, Math.max(8, Number(paperDesign?.marginMm) || 14));
      const marginTwips = Math.round(marginMm * 56.7);
      const basePx = Math.min(18, Math.max(10, Number(paperDesign?.fontSize) || 13));
      const qHalfPt = Math.round(basePx * 1.65);
      const optHalfPt = Math.max(16, qHalfPt - 2);
      const qSpacingTwips = Math.round((Number(paperDesign?.questionSpacing) || 14) * 14);
      const logoFirstPageOnly = paperDesign?.logoFirstPageOnly !== false;
      const showStudentBox = paperDesign?.showStudentBox !== false;
      const showBubbleGrid =
        !includeAnswers &&
        (paperDesign?.showBubbleGrid || paperDesign?.templateStyle === 'bubble_sheet');

      const children: Array<Paragraph | Table> = [];

      // Masthead Info Table (Page 1 Brand Identity)
      children.push(
        new Table({
          width: { size: 100, type: WidthType.PERCENTAGE },
          visuallyRightToLeft: true,
          borders: {
            top: { style: BorderStyle.SINGLE, size: 12, color: '0A192F' },
            bottom: { style: BorderStyle.DOUBLE, size: 12, color: 'C89B3C' },
            left: { style: BorderStyle.SINGLE, size: 6, color: 'CBD5E1' },
            right: { style: BorderStyle.SINGLE, size: 6, color: 'CBD5E1' },
            insideHorizontal: { style: BorderStyle.SINGLE, size: 4, color: 'E2E8F0' },
            insideVertical: { style: BorderStyle.SINGLE, size: 4, color: 'E2E8F0' },
          },
          rows: [
            new TableRow({
              children: [
                new TableCell({
                  children: [
                    new Paragraph({
                      bidirectional: true,
                      alignment: AlignmentType.CENTER,
                      children: [
                        new TextRun({
                          text: 'منصة الأستاذ 𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜 التعليمية',
                          bold: true,
                          size: 28,
                          color: '0A192F',
                        }),
                      ],
                    }),
                    new Paragraph({
                      bidirectional: true,
                      alignment: AlignmentType.CENTER,
                      children: [
                        new TextRun({
                          text: paperDesign?.customHeaderNote
                            ? `${paperDesign.customHeaderNote}  |  01069128848  |  01120296310`
                            : `تواصل: 01069128848  |  01120296310`,
                          size: 20,
                          color: '8A661B',
                        }),
                      ],
                    }),
                  ],
                }),
              ],
            }),
            new TableRow({
              children: [
                new TableCell({
                  children: [
                    new Paragraph({
                      bidirectional: true,
                      alignment: AlignmentType.CENTER,
                      children: [
                        new TextRun({
                          text: `${exam.title}${variantLabel ? ` (نموذج ${variantLabel})` : ''}${
                            includeAnswers ? ' — نموذج الإجابة' : ''
                          }`,
                          bold: true,
                          size: 26,
                          color: '0A192F',
                        }),
                      ],
                    }),
                    new Paragraph({
                      bidirectional: true,
                      alignment: AlignmentType.CENTER,
                      children: [
                        new TextRun({
                          text: `المادة: ${exam.subject}   |   الصف: ${exam.grade} (${exam.system})   |   الزمن: ${exam.durationMinutes} دقيقة   |   الدرجة: ${exam.totalMarks}`,
                          size: 20,
                          color: '334155',
                        }),
                      ],
                    }),
                  ],
                }),
              ],
            }),
          ],
        })
      );

      if (!includeAnswers && showStudentBox) {
        children.push(
          new Paragraph({
            bidirectional: true,
            spacing: { before: 160, after: 120 },
            children: [
              new TextRun({
                text: 'اسم الطالب: .........................................................    المجموعة: .........................    الدرجة: ....... / ' + exam.totalMarks,
                bold: true,
                size: 20,
              }),
            ],
          })
        );
      }

      if (exam.instructions) {
        children.push(
          new Paragraph({
            bidirectional: true,
            spacing: { before: 80, after: 140 },
            children: [
              new TextRun({ text: 'تعليمات الامتحان: ', bold: true, size: 20, color: '0A192F' }),
              new TextRun({ text: exam.instructions, size: 20, color: '475569' }),
            ],
          })
        );
      }

      exam.questions.forEach((q, idx) => {
        children.push(
          new Paragraph({
            bidirectional: true,
            keepNext: true,
            keepLines: true,
            spacing: { before: qSpacingTwips, after: 60 },
            children: [
              new TextRun({
                text: `س${idx + 1} (${q.points} درجة) [${q.type}]: `,
                bold: true,
                size: qHalfPt,
                color: '0A192F',
              }),
              new TextRun({ text: q.prompt, size: qHalfPt, color: '0F172A' }),
            ],
          })
        );

        if (q.options && q.options.length > 0) {
          q.options.forEach((opt, optIdx) => {
            const letter = ['أ', 'ب', 'ج', 'د', 'هـ'][optIdx] || String(optIdx + 1);
            children.push(
              new Paragraph({
                bidirectional: true,
                keepLines: true,
                spacing: { before: 25, after: 25 },
                indent: { right: 360 },
                children: [new TextRun({ text: `${letter}) ${opt}`, size: optHalfPt, color: '1E293B' })],
              })
            );
          });
        } else if (!includeAnswers) {
          children.push(
            new Paragraph({
              bidirectional: true,
              spacing: { before: 70, after: 120 },
              children: [
                new TextRun({
                  text: 'الإجابة: ........................................................................................................................',
                  size: optHalfPt,
                  color: '94A3B8',
                }),
              ],
            })
          );
        }

        if (includeAnswers) {
          children.push(
            new Paragraph({
              bidirectional: true,
              spacing: { before: 60, after: 80 },
              indent: { right: 240 },
              children: [
                new TextRun({ text: 'الإجابة النموذجية: ', bold: true, size: optHalfPt, color: '15803D' }),
                new TextRun({ text: q.correctAnswer || '—', bold: true, size: optHalfPt, color: '166534' }),
              ],
            })
          );
          if (q.explanation) {
            children.push(
              new Paragraph({
                bidirectional: true,
                spacing: { after: 80 },
                indent: { right: 240 },
                children: [
                  new TextRun({ text: 'التوضيح: ', bold: true, size: Math.max(16, optHalfPt - 2), color: '475569' }),
                  new TextRun({ text: q.explanation, size: Math.max(16, optHalfPt - 2), color: '64748B' }),
                ],
              })
            );
          }
        }
      });

      if (showBubbleGrid) {
        const objectiveQs = exam.questions
          .map((q, idx) => ({ q, num: idx + 1 }))
          .filter((item) => item.q.options && item.q.options.length > 0);
        if (objectiveQs.length > 0) {
          children.push(
            new Paragraph({
              bidirectional: true,
              spacing: { before: 240, after: 100 },
              children: [
                new TextRun({
                  text: 'ورقة تظليل الإجابات (Bubble Sheet):',
                  bold: true,
                  size: 22,
                  color: '0A192F',
                }),
              ],
            })
          );
          children.push(
            new Table({
              width: { size: 100, type: WidthType.PERCENTAGE },
              visuallyRightToLeft: true,
              rows: objectiveQs.map(
                (item) =>
                  new TableRow({
                    children: [
                      new TableCell({
                        children: [
                          new Paragraph({
                            bidirectional: true,
                            children: [new TextRun({ text: `س${item.num}`, bold: true, size: 18 })],
                          }),
                        ],
                      }),
                      ...['أ', 'ب', 'ج', 'د'].map(
                        (letter) =>
                          new TableCell({
                            children: [
                              new Paragraph({
                                alignment: AlignmentType.CENTER,
                                children: [new TextRun({ text: `◯ ${letter}`, size: 18 })],
                              }),
                            ],
                          })
                      ),
                    ],
                  })
              ),
            })
          );
        }
      }

      const compactHeader = new Header({
        children: [
          new Paragraph({
            bidirectional: true,
            alignment: AlignmentType.LEFT,
            children: [
              new TextRun({
                text: `${exam.title} — ${exam.subject} (${exam.grade})`,
                size: 16,
                color: '64748B',
              }),
            ],
          }),
        ],
      });

      const doc = new Document({
        sections: [
          {
            properties: {
              titlePage: logoFirstPageOnly,
              page: {
                size: { width: 11906, height: 16838 }, // A4
                margin: {
                  top: marginTwips,
                  right: marginTwips,
                  bottom: marginTwips,
                  left: marginTwips,
                },
              },
            },
            headers: {
              first: new Header({ children: [] }),
              default: logoFirstPageOnly
                ? compactHeader
                : new Header({
                    children: [
                      new Paragraph({
                        bidirectional: true,
                        alignment: AlignmentType.LEFT,
                        children: [
                          new TextRun({
                            text: `𝓜𝓡. 𝒜𝒽𝓂𝑒𝒹 𝒜𝒷𝑜𝑜 — ${exam.subject} — ${exam.grade}`,
                            size: 16,
                            color: '64748B',
                          }),
                        ],
                      }),
                    ],
                  }),
            },
            footers: {
              default: new Footer({
                children: [
                  new Paragraph({
                    bidirectional: true,
                    alignment: AlignmentType.CENTER,
                    children: [
                      new TextRun({ text: 'صفحة ', size: 16, color: '64748B' }),
                      new TextRun({ children: [PageNumber.CURRENT], size: 16, color: '64748B' }),
                      new TextRun({ text: ' — مع تمنيات الأستاذ أحمد أبو بالتوفيق والتفوق', size: 16, color: '64748B' }),
                    ],
                  }),
                ],
              }),
            },
            children,
          },
        ],
      });

      const buffer = await Packer.toBuffer(doc);
      res.setHeader(
        'Content-Type',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      );
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="exam-${includeAnswers ? 'answers' : 'questions'}.docx"`
      );
      res.send(buffer);
    } catch (err) {
      console.error('Word export error:', err);
      res.status(500).json({ error: 'فشل تصدير ملف Word.' });
    }
  });

  // ---------------- Owner-Only Complete Project Source Vault & ZIP Exporter ----------------
  const PROJECT_SOURCE_ROOT = fs.realpathSync(process.cwd());
  const SOURCE_EXCLUDED_DIRS = new Set([
    'node_modules',
    '.git',
    'dist',
    'build',
    'coverage',
    '.next',
    '.aistudio',
    '.cache',
    'tmp',
    '.vscode',
    '.idea',
    '.firebase',
  ]);
  const SOURCE_BINARY_EXTS = new Set([
    '.png',
    '.jpg',
    '.jpeg',
    '.webp',
    '.gif',
    '.ico',
    '.woff',
    '.woff2',
    '.ttf',
    '.eot',
    '.pdf',
  ]);

  type SourceFileCategory = 'frontend' | 'services' | 'backend' | 'firebase' | 'config' | 'assets';

  interface CollectedSourceFile {
    path: string;
    name: string;
    directory: string;
    ext: string;
    sizeBytes: number;
    isBinary: boolean;
    category: SourceFileCategory;
    absPath: string;
  }

  function isBlockedSourceName(fileName: string): boolean {
    const lower = fileName.toLowerCase();
    if (lower === '.ds_store' || lower === 'thumbs.db') return true;
    if (lower.endsWith('.log')) return true;
    if (lower === '.env' || (lower.startsWith('.env.') && lower !== '.env.example')) return true;
    if (
      lower.endsWith('.pem') ||
      lower.endsWith('.key') ||
      lower.endsWith('.p12') ||
      lower.endsWith('.pfx') ||
      lower.endsWith('.crt') ||
      lower.endsWith('.secret')
    ) {
      return true;
    }
    if (
      lower.includes('serviceaccount') ||
      lower.includes('service-account') ||
      lower.includes('credentials') ||
      lower.includes('private-key')
    ) {
      return true;
    }
    return false;
  }

  function categorizeSourceFile(relPath: string, ext: string): SourceFileCategory {
    if (
      relPath.startsWith('public/') ||
      relPath.startsWith('src/assets/') ||
      SOURCE_BINARY_EXTS.has(ext)
    ) {
      return 'assets';
    }
    if (
      relPath.includes('firebase') ||
      relPath === 'firestore.rules' ||
      relPath === 'security_spec.md'
    ) {
      return 'firebase';
    }
    if (relPath === 'server.ts') {
      return 'backend';
    }
    if (relPath.startsWith('src/services/') || relPath.startsWith('src/lib/') || relPath.startsWith('src/hooks/')) {
      return 'services';
    }
    if (relPath.startsWith('src/')) {
      return 'frontend';
    }
    return 'config';
  }

  function collectProjectSourceFiles(
    dirAbs: string = PROJECT_SOURCE_ROOT,
    relBase = '',
    out: CollectedSourceFile[] = []
  ): CollectedSourceFile[] {
    const entries = fs.readdirSync(dirAbs, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const name = entry.name;
      const nextRel = relBase ? `${relBase}/${name}` : name;
      const nextAbs = path.join(dirAbs, name);

      if (entry.isDirectory()) {
        if (SOURCE_EXCLUDED_DIRS.has(name) || name.startsWith('.git')) continue;
        collectProjectSourceFiles(nextAbs, nextRel, out);
        continue;
      }

      if (!entry.isFile()) continue;
      if (isBlockedSourceName(name)) continue;

      const stat = fs.statSync(nextAbs);
      if (stat.size > 25 * 1024 * 1024) continue;
      const ext = path.extname(name).toLowerCase();
      const directory = relBase || '.';
      out.push({
        path: nextRel,
        name,
        directory,
        ext,
        sizeBytes: stat.size,
        isBinary: SOURCE_BINARY_EXTS.has(ext),
        category: categorizeSourceFile(nextRel, ext),
        absPath: nextAbs,
      });
    }

    if (relBase === '') {
      out.sort((a, b) => a.path.localeCompare(b.path));
    }
    return out;
  }

  function resolveSafeProjectFile(rawRelPath: string): { safeRel: string; absPath: string } | null {
    if (typeof rawRelPath !== 'string' || !rawRelPath.trim() || rawRelPath.includes('\0')) {
      return null;
    }
    const normalized = rawRelPath.replace(/\\/g, '/').replace(/^\/+/, '').trim();
    if (!normalized || normalized.split('/').some((seg) => seg === '..' || seg === '.')) {
      return null;
    }
    const segments = normalized.split('/');
    if (segments.some((seg) => SOURCE_EXCLUDED_DIRS.has(seg) || isBlockedSourceName(seg))) {
      return null;
    }
    const resolved = path.resolve(PROJECT_SOURCE_ROOT, normalized);
    if (!resolved.startsWith(PROJECT_SOURCE_ROOT + path.sep)) {
      return null;
    }
    if (!fs.existsSync(resolved)) return null;
    const realResolved = fs.realpathSync(resolved);
    if (!realResolved.startsWith(PROJECT_SOURCE_ROOT + path.sep)) {
      return null;
    }
    const stat = fs.statSync(realResolved);
    if (!stat.isFile()) return null;
    return { safeRel: normalized, absPath: realResolved };
  }

  function buildPlatformRunGuideMarkdown(fileCount: number): string {
    return `# منصة الأستاذ أحمد أبو التعليمية والإدارية — دليل التشغيل الكامل

هذه الحزمة تحتوي على **الكود المصدري الكامل للمنصة (${fileCount} ملفاً)** شاملاً جميع الإضافات والواجهات والخدمات:
- الواجهة الأمامية الكاملة (React 19 + TypeScript + Tailwind CSS v4 + PWA)
- الخادم الخلفي (\`server.ts\`) مع نقاط نهاية الذكاء الاصطناعي، OCR، تصدير Word، التصحيح المشفّر، وساحة التحدي المباشر (WebSocket)
- إعدادات Firebase Firestore ومخطط البيانات وقواعد الأمان (\`firestore.rules\` و \`firebase-blueprint.json\` و \`firebase-applet-config.json\`)
- الأصول والصور والأيقونات الكاملة (\`src/assets/\` و \`public/\`)

## خطوات التشغيل على أي جهاز أو خادم آخر

1. **تثبيت Node.js** (الإصدار 20 أو أحدث).
2. **تثبيت الحزم والاعتماديات:**
   \`\`\`bash
   npm install
   \`\`\`
3. **إعداد متغيرات البيئة (ملف \`.env\`):**
   انسخ ملف \`.env.example\` إلى ملف جديد باسم \`.env\` وأضف القيم التالية:
   \`\`\`env
   GEMINI_API_KEY="ضع_مفتاح_جيميني_هنا"
   EXAM_SEAL_SECRET="اكتب_عبارة_سرية_طويلة_لتشفير_الامتحانات"
   \`\`\`
   *(ملاحظة أمنية: هذا الملف مستثنى من حزمة ZIP تلقائياً للحفاظ على سرية مفاتيحك؛ أنشئه يدوياً في بيئة الاستضافة الجديدة فقط).*

4. **التشغيل في وضع التطوير:**
   \`\`\`bash
   npm run dev
   \`\`\`
   سيعمل الموقع والخادم معاً على المنفذ \`3000\` (\`http://localhost:3000\`).

5. **البناء والتشغيل في وضع الإنتاج (Production / VPS / Render / Railway):**
   \`\`\`bash
   npm run build
   NODE_ENV=production npm start
   \`\`\`

6. **نشر قواعد أمان Firebase (عند الحاجة):**
   \`\`\`bash
   firebase deploy --only firestore:rules
   \`\`\`
`;
  }

  app.get('/api/project-source/tree', verifyFirebaseBearer, (req: AuthenticatedRequest, res: Response) => {
    if (!req.authUser?.isOwner) {
      res.status(403).json({ error: 'استعراض وتنزيل الأكواد المصدرية مخصص لمالك المنصة فقط.' });
      return;
    }
    try {
      const files = collectProjectSourceFiles();
      const totalBytes = files.reduce((sum, f) => sum + f.sizeBytes, 0);
      const countsByCategory: Record<SourceFileCategory, number> = {
        frontend: 0,
        services: 0,
        backend: 0,
        firebase: 0,
        config: 0,
        assets: 0,
      };
      for (const f of files) {
        countsByCategory[f.category] += 1;
      }
      res.json({
        projectName: 'mr-ahmed-aboo-platform',
        generatedAt: new Date().toISOString(),
        totalFiles: files.length,
        totalBytes,
        countsByCategory,
        files: files.map(({ absPath: _abs, ...rest }) => rest),
      });
    } catch (err) {
      console.error('Source tree error:', err);
      res.status(500).json({ error: 'تعذر قراءة قائمة ملفات المشروع.' });
    }
  });

  app.get('/api/project-source/file', verifyFirebaseBearer, (req: AuthenticatedRequest, res: Response) => {
    if (!req.authUser?.isOwner) {
      res.status(403).json({ error: 'استعراض الأكواد المصدرية مخصص لمالك المنصة فقط.' });
      return;
    }
    const rawPath = typeof req.query.path === 'string' ? req.query.path : '';
    const resolved = resolveSafeProjectFile(rawPath);
    if (!resolved) {
      res.status(400).json({ error: 'المسار المطلوب غير صالح أو محظور لأسباب أمنية.' });
      return;
    }
    try {
      const stat = fs.statSync(resolved.absPath);
      const ext = path.extname(resolved.safeRel).toLowerCase();
      const isBinary = SOURCE_BINARY_EXTS.has(ext);
      if (isBinary) {
        res.json({
          path: resolved.safeRel,
          isBinary: true,
          sizeBytes: stat.size,
          lineCount: 0,
          content: '',
        });
        return;
      }
      if (stat.size > 2 * 1024 * 1024) {
        res.status(413).json({ error: 'حجم الملف كبير للعرض المباشر؛ يمكنك تنزيله ضمن حزمة ZIP الكاملة.' });
        return;
      }
      const content = fs.readFileSync(resolved.absPath, 'utf8');
      res.json({
        path: resolved.safeRel,
        isBinary: false,
        sizeBytes: stat.size,
        lineCount: content.split('\n').length,
        content,
      });
    } catch (err) {
      console.error('Source file read error:', err);
      res.status(500).json({ error: 'تعذر قراءة محتوى الملف.' });
    }
  });

  async function handleZipArchiveDownload(
    req: AuthenticatedRequest,
    res: Response,
    scope: string,
    selectedPaths?: string[]
  ) {
    if (!req.authUser?.isOwner) {
      res.status(403).json({ error: 'تصدير حزمة الأكواد الكاملة مخصص لمالك المنصة فقط.' });
      return;
    }
    try {
      const allFiles = collectProjectSourceFiles();
      let targetFiles = allFiles;

      if (scope === 'selected' && Array.isArray(selectedPaths) && selectedPaths.length > 0) {
        const selectedSet = new Set(selectedPaths.map((p) => String(p).replace(/\\/g, '/').replace(/^\/+/, '')));
        targetFiles = allFiles.filter((f) => selectedSet.has(f.path));
      } else if (scope === 'frontend') {
        targetFiles = allFiles.filter(
          (f) => f.path.startsWith('src/') || f.path === 'index.html' || f.path === 'package.json'
        );
      } else if (scope === 'backend') {
        targetFiles = allFiles.filter(
          (f) =>
            f.category === 'backend' ||
            f.category === 'firebase' ||
            f.category === 'config'
        );
      } else if (scope === 'code_only') {
        targetFiles = allFiles.filter((f) => !f.isBinary);
      }

      if (targetFiles.length === 0) {
        res.status(400).json({ error: 'لا توجد ملفات مطابقة لنطاق التصدير المحدد.' });
        return;
      }

      const zip = new JSZip();
      const rootFolderName = 'mr-ahmed-aboo-platform';
      const rootFolder = zip.folder(rootFolderName) || zip;

      for (const f of targetFiles) {
        const safe = resolveSafeProjectFile(f.path);
        if (!safe) continue;
        const data = fs.readFileSync(safe.absPath);
        rootFolder.file(safe.safeRel, data, { binary: f.isBinary });
      }

      rootFolder.file('PLATFORM_RUN_GUIDE.md', buildPlatformRunGuideMarkdown(targetFiles.length));

      const zipBuffer = await zip.generateAsync({
        type: 'nodebuffer',
        compression: 'DEFLATE',
        compressionOptions: { level: 6 },
      });

      const dateTag = new Date().toISOString().slice(0, 10);
      const scopeSuffix =
        scope === 'all'
          ? 'full-source'
          : scope === 'selected'
          ? 'selected'
          : scope.replace(/[^a-z0-9_-]/gi, '');

      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="mr-ahmed-aboo-platform-${scopeSuffix}-${dateTag}.zip"`
      );
      res.setHeader('Content-Length', String(zipBuffer.length));
      res.send(zipBuffer);
    } catch (err) {
      console.error('Project ZIP export error:', err);
      res.status(500).json({ error: 'تعذر إنشاء ملف ZIP للمشروع.' });
    }
  }

  app.get('/api/project-source/download-zip', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    const scope = typeof req.query.scope === 'string' ? req.query.scope : 'all';
    await handleZipArchiveDownload(req, res, scope);
  });

  app.post('/api/project-source/download-zip', verifyFirebaseBearer, async (req: AuthenticatedRequest, res: Response) => {
    const body = (req.body || {}) as { scope?: string; paths?: string[] };
    const scope = typeof body.scope === 'string' ? body.scope : 'all';
    await handleZipArchiveDownload(req, res, scope, Array.isArray(body.paths) ? body.paths : undefined);
  });

  const httpServer = http.createServer(app);

  // Real-Time Live Classroom Quiz Arena WebSocket (/ws/live-quiz)
  interface LiveQuizQuestionInternal {
    id: string;
    prompt: string;
    options: string[];
    correctAnswer: string;
    explanation?: string;
    points: number;
  }
  interface LiveQuizParticipantInternal {
    studentId: string;
    studentName: string;
    groupId?: string;
    uid: string;
    score: number;
    correctCount: number;
    answeredCurrent: boolean;
    lastCorrect?: boolean;
    lastPointsEarned?: number;
    ws: WebSocket | null;
  }
  interface LiveQuizRoom {
    pin: string;
    title: string;
    subject: string;
    grade: string;
    hostUid: string;
    hostWs: WebSocket | null;
    status: 'lobby' | 'question' | 'reveal' | 'ended';
    currentIndex: number;
    questionStartedAtMs: number;
    durationSec: number;
    questions: LiveQuizQuestionInternal[];
    participants: Map<string, LiveQuizParticipantInternal>;
    answersByQuestion: Map<number, Map<string, { answer: string; elapsedMs: number }>>;
    createdAtMs: number;
  }

  const liveQuizRooms = new Map<string, LiveQuizRoom>();
  const wssLiveQuiz = new WebSocketServer({ server: httpServer, path: '/ws/live-quiz' });

  const buildPublicLeaderboard = (room: LiveQuizRoom) =>
    Array.from(room.participants.values())
      .map((p) => ({
        studentId: p.studentId,
        studentName: p.studentName,
        groupId: p.groupId || '',
        score: p.score,
        correctCount: p.correctCount,
        answeredCurrent: p.answeredCurrent,
        lastCorrect: p.lastCorrect,
        lastPointsEarned: p.lastPointsEarned || 0,
      }))
      .sort((a, b) => b.score - a.score || b.correctCount - a.correctCount);

  const buildRoomSnapshot = (room: LiveQuizRoom, forHost: boolean) => {
    const q = room.currentIndex >= 0 ? room.questions[room.currentIndex] : null;
    const answeredCount = Array.from(room.participants.values()).filter((p) => p.answeredCurrent).length;
    return {
      type: 'room_state',
      pin: room.pin,
      title: room.title,
      subject: room.subject,
      grade: room.grade,
      status: room.status,
      currentIndex: room.currentIndex,
      totalQuestions: room.questions.length,
      durationSec: room.durationSec,
      questionStartedAtMs: room.questionStartedAtMs,
      answeredCount,
      participantCount: room.participants.size,
      leaderboard: buildPublicLeaderboard(room),
      question: q
        ? {
            id: q.id,
            prompt: q.prompt,
            options: q.options,
            points: q.points,
            ...(room.status === 'reveal' || room.status === 'ended' || forHost
              ? { correctAnswer: q.correctAnswer, explanation: q.explanation || '' }
              : {}),
          }
        : null,
    };
  };

  const broadcastRoomState = (room: LiveQuizRoom) => {
    if (room.hostWs && room.hostWs.readyState === 1) {
      room.hostWs.send(JSON.stringify(buildRoomSnapshot(room, true)));
    }
    const studentPayload = JSON.stringify(buildRoomSnapshot(room, false));
    for (const p of room.participants.values()) {
      if (p.ws && p.ws.readyState === 1) {
        p.ws.send(studentPayload);
      }
    }
  };

  const revealRoomQuestion = (room: LiveQuizRoom) => {
    if (room.status !== 'question') return;
    const q = room.questions[room.currentIndex];
    if (!q) return;
    const ansMap = room.answersByQuestion.get(room.currentIndex) || new Map();
    const normCorrect = normalizeArabicText(q.correctAnswer);

    for (const p of room.participants.values()) {
      const sub = ansMap.get(p.studentId);
      if (!sub) {
        p.lastCorrect = false;
        p.lastPointsEarned = 0;
        continue;
      }
      const isRight = normalizeArabicText(sub.answer) === normCorrect;
      if (isRight) {
        const maxMs = Math.max(5000, room.durationSec * 1000);
        const speedRatio = Math.max(0, Math.min(1, (maxMs - sub.elapsedMs) / maxMs));
        const earned = Math.round(100 + speedRatio * 100);
        p.score += earned;
        p.correctCount += 1;
        p.lastCorrect = true;
        p.lastPointsEarned = earned;
      } else {
        p.lastCorrect = false;
        p.lastPointsEarned = 0;
      }
    }
    room.status = 'reveal';
    broadcastRoomState(room);
  };

  wssLiveQuiz.on('connection', (ws) => {
    let boundUser: VerifiedUser | null = null;
    let boundPin: string | null = null;
    let boundStudentId: string | null = null;
    let isRoomHost = false;

    ws.on('message', async (raw) => {
      try {
        const msg = JSON.parse(raw.toString()) as {
          type: string;
          token?: string;
          pin?: string;
          title?: string;
          subject?: string;
          grade?: string;
          durationSec?: number;
          questions?: LiveQuizQuestionInternal[];
          studentId?: string;
          studentName?: string;
          groupId?: string;
          answer?: string;
        };

        if (msg.token && !boundUser) {
          const decoded = await adminAuth.verifyIdToken(msg.token);
          const email = (decoded.email || '').toLowerCase();
          boundUser = {
            uid: decoded.uid,
            email,
            emailVerified: Boolean(decoded.email_verified),
            isOwner: email === OWNER_EMAIL && Boolean(decoded.email_verified),
          };
        }

        if (!boundUser) {
          ws.send(JSON.stringify({ type: 'error', message: 'يرجى التحقق من الهوية للانضمام إلى الساحة.' }));
          return;
        }

        if (msg.type === 'teacher_create_room') {
          const token = msg.token || '';
          const allowed = await verifyTeacherViaFirestore(token, boundUser);
          if (!allowed) {
            ws.send(JSON.stringify({ type: 'error', message: 'إنشاء مسابقة الحصة مخصص للمعلم فقط.' }));
            return;
          }
          const qs = Array.isArray(msg.questions) ? msg.questions.filter((q) => q.prompt && q.options?.length >= 2) : [];
          if (qs.length === 0) {
            ws.send(JSON.stringify({ type: 'error', message: 'يرجى اختيار أسئلة موضوعية صالحة (خياران فأكثر).' }));
            return;
          }
          let pin = String(Math.floor(100000 + Math.random() * 900000));
          while (liveQuizRooms.has(pin)) {
            pin = String(Math.floor(100000 + Math.random() * 900000));
          }
          const room: LiveQuizRoom = {
            pin,
            title: msg.title || 'تحدي الحصة المباشر',
            subject: msg.subject || 'عام',
            grade: msg.grade || 'عام',
            hostUid: boundUser.uid,
            hostWs: ws,
            status: 'lobby',
            currentIndex: -1,
            questionStartedAtMs: 0,
            durationSec: Math.min(90, Math.max(10, Number(msg.durationSec) || 25)),
            questions: qs.slice(0, 30),
            participants: new Map(),
            answersByQuestion: new Map(),
            createdAtMs: Date.now(),
          };
          liveQuizRooms.set(pin, room);
          boundPin = pin;
          isRoomHost = true;
          broadcastRoomState(room);
          return;
        }

        if (msg.type === 'student_join') {
          const pin = String(msg.pin || '').trim();
          const room = liveQuizRooms.get(pin);
          if (!room) {
            ws.send(JSON.stringify({ type: 'error', message: 'رمز المسابقة (PIN) غير صحيح أو انتهت المسابقة.' }));
            return;
          }
          if (room.status === 'ended') {
            ws.send(JSON.stringify({ type: 'error', message: 'لقد انتهى هذا التحدي بالفعل.' }));
            return;
          }
          const sid = msg.studentId || boundUser.uid;
          boundPin = pin;
          boundStudentId = sid;
          const existing = room.participants.get(sid);
          if (existing) {
            existing.ws = ws;
            existing.uid = boundUser.uid;
          } else {
            room.participants.set(sid, {
              studentId: sid,
              studentName: msg.studentName || 'طالب مشارك',
              groupId: msg.groupId || '',
              uid: boundUser.uid,
              score: 0,
              correctCount: 0,
              answeredCurrent: false,
              ws,
            });
          }
          broadcastRoomState(room);
          return;
        }

        const room = boundPin ? liveQuizRooms.get(boundPin) : undefined;
        if (!room) {
          ws.send(JSON.stringify({ type: 'error', message: 'الغرفة غير موجودة.' }));
          return;
        }

        if (msg.type === 'teacher_next_question' && isRoomHost && boundUser.uid === room.hostUid) {
          const nextIdx = room.currentIndex + 1;
          if (nextIdx >= room.questions.length) {
            room.status = 'ended';
            broadcastRoomState(room);
            return;
          }
          room.currentIndex = nextIdx;
          room.status = 'question';
          room.questionStartedAtMs = Date.now();
          for (const p of room.participants.values()) {
            p.answeredCurrent = false;
            p.lastCorrect = undefined;
            p.lastPointsEarned = 0;
          }
          broadcastRoomState(room);
          return;
        }

        if (msg.type === 'teacher_reveal_answer' && isRoomHost && boundUser.uid === room.hostUid) {
          revealRoomQuestion(room);
          return;
        }

        if (msg.type === 'teacher_end_session' && isRoomHost && boundUser.uid === room.hostUid) {
          if (room.status === 'question') {
            revealRoomQuestion(room);
          }
          room.status = 'ended';
          broadcastRoomState(room);
          return;
        }

        if (msg.type === 'student_submit_answer' && boundStudentId) {
          if (room.status !== 'question') return;
          const participant = room.participants.get(boundStudentId);
          if (!participant || participant.answeredCurrent) return;
          const qMap = room.answersByQuestion.get(room.currentIndex) || new Map();
          if (qMap.has(boundStudentId)) return;
          const elapsedMs = Math.max(0, Date.now() - room.questionStartedAtMs);
          qMap.set(boundStudentId, { answer: String(msg.answer || ''), elapsedMs });
          room.answersByQuestion.set(room.currentIndex, qMap);
          participant.answeredCurrent = true;

          // If everyone answered, auto-reveal!
          const allAnswered =
            room.participants.size > 0 &&
            Array.from(room.participants.values()).every((p) => p.answeredCurrent);
          if (allAnswered) {
            revealRoomQuestion(room);
          } else {
            broadcastRoomState(room);
          }
        }
      } catch (err) {
        console.warn('LiveQuiz WS error:', err);
        ws.send(JSON.stringify({ type: 'error', message: 'حدث خطأ في الاتصال بساحة التحدي.' }));
      }
    });

    ws.on('close', () => {
      if (boundPin) {
        const room = liveQuizRooms.get(boundPin);
        if (room) {
          if (isRoomHost && room.hostWs === ws) {
            room.hostWs = null;
          } else if (boundStudentId) {
            const p = room.participants.get(boundStudentId);
            if (p && p.ws === ws) p.ws = null;
          }
        }
      }
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const disableHmr = process.env.DISABLE_HMR === 'true';
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        allowedHosts: true,
        hmr: !disableHmr,
        ws: disableHmr ? false : { server: httpServer, path: '/vite-hmr' },
        watch: disableHmr ? null : {},
      },
      appType: 'spa',
    });

    if (disableHmr) {
      app.get('/@vite/client', async (_req, res, next) => {
        try {
          const transformed = await vite.transformRequest('/@vite/client');
          if (!transformed) return next();
          const safeCode = transformed.code.replace(
            /let wsTransport = createWebSocketModuleRunnerTransport\(\{[\s\S]*?\}\);/,
            'let wsTransport = { connect: async () => {}, disconnect: async () => {}, send: () => {} };'
          );
          res.type('application/javascript').send(safeCode);
        } catch (err) {
          next(err);
        }
      });
    }

    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('/{*splat}', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`MR. Ahmed Aboo Platform running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
