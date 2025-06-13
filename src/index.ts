// Secure Password Generator TypeScript Project
import * as crypto from "crypto";

interface PasswordOptions {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
  excludeSimilar: boolean;
  customCharacters?: string;
}

interface PasswordStrength {
  score: number; // 0-100
  level: "Very Weak" | "Weak" | "Fair" | "Good" | "Strong" | "Very Strong";
  feedback: string[];
}

class PasswordGenerator {
  private static readonly UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static readonly LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
  private static readonly NUMBERS = "0123456789";
  private static readonly SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?";
  private static readonly SIMILAR_CHARS = "il1Lo0O";

  /**
   * セキュアなパスワードを生成
   */
  generatePassword(options: PasswordOptions): string {
    // 文字セットを構築
    let characterSet = "";
    let guaranteedChars = "";

    if (options.includeUppercase) {
      const uppercase = options.excludeSimilar
        ? this.removeSimilarChars(PasswordGenerator.UPPERCASE)
        : PasswordGenerator.UPPERCASE;
      characterSet += uppercase;
      guaranteedChars += this.getRandomChar(uppercase);
    }

    if (options.includeLowercase) {
      const lowercase = options.excludeSimilar
        ? this.removeSimilarChars(PasswordGenerator.LOWERCASE)
        : PasswordGenerator.LOWERCASE;
      characterSet += lowercase;
      guaranteedChars += this.getRandomChar(lowercase);
    }

    if (options.includeNumbers) {
      const numbers = options.excludeSimilar
        ? this.removeSimilarChars(PasswordGenerator.NUMBERS)
        : PasswordGenerator.NUMBERS;
      characterSet += numbers;
      guaranteedChars += this.getRandomChar(numbers);
    }

    if (options.includeSymbols) {
      characterSet += PasswordGenerator.SYMBOLS;
      guaranteedChars += this.getRandomChar(PasswordGenerator.SYMBOLS);
    }

    if (options.customCharacters) {
      characterSet += options.customCharacters;
    }

    if (characterSet.length === 0) {
      throw new Error("少なくとも1つの文字種類を選択してください");
    }

    // パスワード生成
    let password = guaranteedChars;
    const remainingLength = options.length - guaranteedChars.length;

    for (let i = 0; i < remainingLength; i++) {
      password += this.getRandomChar(characterSet);
    }

    // パスワードをシャッフル
    return this.shuffleString(password);
  }

  /**
   * 複数のパスワードを生成
   */
  generateMultiplePasswords(options: PasswordOptions, count: number): string[] {
    const passwords: string[] = [];
    for (let i = 0; i < count; i++) {
      passwords.push(this.generatePassword(options));
    }
    return passwords;
  }

  /**
   * パスワードの強度を評価
   */
  analyzePasswordStrength(password: string): PasswordStrength {
    let score = 0;
    const feedback: string[] = [];

    // 長さのチェック
    if (password.length >= 12) {
      score += 25;
    } else if (password.length >= 8) {
      score += 15;
    } else {
      feedback.push("パスワードは最低8文字以上にしてください");
    }

    // 文字種類のチェック
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);

    const varietyCount = [hasUpper, hasLower, hasNumber, hasSymbol].filter(
      Boolean
    ).length;
    score += varietyCount * 15;

    if (!hasUpper) feedback.push("大文字を含めることを推奨します");
    if (!hasLower) feedback.push("小文字を含めることを推奨します");
    if (!hasNumber) feedback.push("数字を含めることを推奨します");
    if (!hasSymbol) feedback.push("記号を含めることを推奨します");

    // 繰り返し文字のチェック
    const repeatedChars = password.match(/(.)\1{2,}/g);
    if (repeatedChars) {
      score -= repeatedChars.length * 10;
      feedback.push("同じ文字の連続使用を避けてください");
    }

    // 一般的なパターンのチェック
    const commonPatterns = ["123", "abc", "password", "qwerty"];
    const hasCommonPattern = commonPatterns.some((pattern) =>
      password.toLowerCase().includes(pattern)
    );
    if (hasCommonPattern) {
      score -= 20;
      feedback.push("一般的なパターンの使用を避けてください");
    }

    // スコアを0-100に正規化
    score = Math.max(0, Math.min(100, score));

    // レベル判定
    let level: PasswordStrength["level"];
    if (score >= 90) level = "Very Strong";
    else if (score >= 75) level = "Strong";
    else if (score >= 60) level = "Good";
    else if (score >= 40) level = "Fair";
    else if (score >= 20) level = "Weak";
    else level = "Very Weak";

    if (feedback.length === 0) {
      feedback.push("優秀なパスワードです！");
    }

    return { score, level, feedback };
  }

  /**
   * 記憶しやすいパスワードを生成（単語ベース）
   */
  generateMemorablePassword(wordCount: number = 4): string {
    const words = [
      "Apple",
      "Ocean",
      "Mountain",
      "River",
      "Forest",
      "Cloud",
      "Storm",
      "Fire",
      "Stone",
      "Bridge",
      "Castle",
      "Garden",
      "Music",
      "Dance",
      "Dream",
      "Light",
      "Shadow",
      "Moon",
      "Star",
      "Wind",
      "Rain",
      "Snow",
      "Thunder",
      "Lightning",
    ];

    const selectedWords: string[] = [];
    for (let i = 0; i < wordCount; i++) {
      const randomIndex = crypto.randomInt(0, words.length);
      selectedWords.push(words[randomIndex]);
    }

    // 数字と記号を追加
    const randomNumber = crypto.randomInt(10, 99);
    const symbols = ["!", "@", "#", "$", "%"];
    const randomSymbol = symbols[crypto.randomInt(0, symbols.length)];

    return selectedWords.join("-") + randomNumber + randomSymbol;
  }

  private getRandomChar(charset: string): string {
    const randomIndex = crypto.randomInt(0, charset.length);
    return charset[randomIndex];
  }

  private removeSimilarChars(charset: string): string {
    return charset
      .split("")
      .filter((char) => !PasswordGenerator.SIMILAR_CHARS.includes(char))
      .join("");
  }

  private shuffleString(str: string): string {
    const array = str.split("");
    for (let i = array.length - 1; i > 0; i--) {
      const j = crypto.randomInt(0, i + 1);
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array.join("");
  }
}

// デモンストレーション
function demonstratePasswordGenerator(): void {
  const generator = new PasswordGenerator();

  console.log("=== パスワード生成ツール デモ ===\n");

  // 標準的なパスワード生成
  const standardOptions: PasswordOptions = {
    length: 16,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: true,
    excludeSimilar: true,
  };

  console.log("🔐 標準パスワード（16文字）:");
  const standardPassword = generator.generatePassword(standardOptions);
  console.log(`   ${standardPassword}`);

  const strength = generator.analyzePasswordStrength(standardPassword);
  console.log(`   強度: ${strength.level} (${strength.score}/100)`);
  console.log(`   評価: ${strength.feedback.join(", ")}\n`);

  // 複数パスワード生成
  console.log("🔐 複数パスワード生成（3個）:");
  const multiplePasswords = generator.generateMultiplePasswords(
    standardOptions,
    3
  );
  multiplePasswords.forEach((password, index) => {
    console.log(`   ${index + 1}. ${password}`);
  });

  // 記憶しやすいパスワード
  console.log("\n🧠 記憶しやすいパスワード:");
  const memorablePassword = generator.generateMemorablePassword();
  console.log(`   ${memorablePassword}`);

  const memorableStrength =
    generator.analyzePasswordStrength(memorablePassword);
  console.log(
    `   強度: ${memorableStrength.level} (${memorableStrength.score}/100)\n`
  );

  // 異なる設定での生成例
  console.log("⚙️ カスタム設定例:");

  const simpleOptions: PasswordOptions = {
    length: 8,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: false,
    excludeSimilar: false,
  };

  console.log(
    `   シンプル（8文字、記号なし）: ${generator.generatePassword(simpleOptions)}`
  );

  const complexOptions: PasswordOptions = {
    length: 24,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: true,
    excludeSimilar: true,
  };

  console.log(
    `   複雑（24文字、フル機能）: ${generator.generatePassword(complexOptions)}`
  );
}

// コマンドライン引数処理
function handleCommandLineArgs(): void {
  const args = process.argv.slice(2);
  const generator = new PasswordGenerator();

  if (args.length === 0) {
    demonstratePasswordGenerator();
    return;
  }

  const command = args[0].toLowerCase();

  switch (command) {
    case "generate":
    case "gen":
      const options: PasswordOptions = {
        length: parseInt(args[1]) || 12,
        includeUppercase: !args.includes("--no-upper"),
        includeLowercase: !args.includes("--no-lower"),
        includeNumbers: !args.includes("--no-numbers"),
        includeSymbols: !args.includes("--no-symbols"),
        excludeSimilar: args.includes("--exclude-similar"),
      };

      const count = args.includes("--count")
        ? parseInt(args[args.indexOf("--count") + 1]) || 1
        : 1;

      if (count === 1) {
        const password = generator.generatePassword(options);
        console.log(password);
      } else {
        const passwords = generator.generateMultiplePasswords(options, count);
        passwords.forEach((password, index) => {
          console.log(`${index + 1}. ${password}`);
        });
      }
      break;

    case "memorable":
      const wordCount = parseInt(args[1]) || 4;
      console.log(generator.generateMemorablePassword(wordCount));
      break;

    case "analyze":
      if (args.length < 2) {
        console.log('使用法: npm run dev analyze "パスワード"');
        return;
      }
      const password = args[1];
      const analysis = generator.analyzePasswordStrength(password);
      console.log(`強度: ${analysis.level} (${analysis.score}/100)`);
      console.log(`評価: ${analysis.feedback.join(", ")}`);
      break;

    default:
      console.log("使用可能なコマンド:");
      console.log("  generate [長さ] [オプション] - パスワード生成");
      console.log("  memorable [単語数] - 記憶しやすいパスワード生成");
      console.log('  analyze "パスワード" - パスワード強度分析');
      console.log("\nオプション:");
      console.log("  --no-upper, --no-lower, --no-numbers, --no-symbols");
      console.log("  --exclude-similar, --count <数>");
  }
}

// メイン実行
if (require.main === module) {
  handleCommandLineArgs();
}

export { PasswordGenerator, type PasswordOptions, type PasswordStrength };