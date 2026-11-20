import { Injectable } from "@angular/core";
import { AppNativeService } from "./app-native.service";
import { MessageToasterService, ToastLevel } from "./message-toaster.service";

/**
 * Watches the in-app SSO verification window for approval and, when configured, fills in the AWS
 * IAM Identity Center sign-in pages.
 *
 * Filling is opt-in: it needs ~/.Leapp/sso-autofill.json. The file maps an Identity Center
 * directory id (the `d-…` segment of the sign-in URL) to commands that print each credential:
 *
 *   { "d-0123456789": { "username": ["/path/to/cmd", "arg"], "password": [...], "otp": [...] } }
 *
 * Commands run without a shell; a leading "~/" in the program path is expanded. Each step is
 * submitted at most once: if the page does not move on (wrong password, rejected code), filling
 * stops and the user finishes in the window, so a bad credential is never retried.
 */

type Field = "username" | "password" | "otp";
type DirectoryConfig = Record<Field, string[]>;
type AutofillConfig = Record<string, DirectoryConfig>;
type Step = "username" | "password" | "mfa" | "confirm" | "approved" | "wait";
interface PageState {
  directory: string | null;
  step: Step;
}
// The parts of Electron's WebContents this service uses. Importing the type from "electron" pulls
// electron.d.ts into the Angular build, whose Node typings conflict with the project's.
interface VerificationWebContents {
  isDestroyed(): boolean;
  executeJavaScript(code: string): Promise<unknown>;
  insertText(text: string): Promise<void>;
}

const configFile = ".Leapp/sso-autofill.json";
const fields: Field[] = ["username", "password", "otp"];
const pollMs = 1000;
const stepTimeoutMs = 15_000;
const watchTimeoutMs = 600_000;
const commandTimeoutMs = 20_000;
const textInputs = "input[type=text],input[type=email]";

const stepField: Partial<Record<Step, { field: Field; selector: string }>> = {
  username: { field: "username", selector: textInputs },
  password: { field: "password", selector: "input[type=password]" },
  mfa: { field: "otp", selector: textInputs },
};

// Runs in the sign-in page. Returns the directory id from the URL and the step the page shows.
const detectStep = `(() => {
  const visible = (el) => el.offsetParent !== null && !el.disabled;
  const any = (selector) => [...document.querySelectorAll(selector)].some(visible);
  const text = document.body ? document.body.innerText : "";
  const directory = (location.pathname.match(/\\/platform\\/(d-[0-9a-z]+)/) || [])[1] || null;
  const button = [...document.querySelectorAll("button")].some((b) => visible(b) && /^(Confirm and continue|Allow access)$/i.test(b.innerText.trim()));
  let step = "wait";
  if (/Request approved/i.test(text)) step = "approved";
  else if (button) step = "confirm";
  else if (any("input[type=password]")) step = "password";
  else if (any(${JSON.stringify(textInputs)})) step = /MFA code|six digit code/i.test(text) ? "mfa" : "username";
  return { directory, step };
})()`;

const focusInput = (selector: string): string => `(() => {
  const el = [...document.querySelectorAll(${JSON.stringify(selector)})].find((e) => e.offsetParent !== null && !e.disabled);
  if (!el) return false;
  el.focus();
  el.select();
  return true;
})()`;

const clickSubmit = `(() => {
  const b = [...document.querySelectorAll("button")].find((e) => e.offsetParent !== null && !e.disabled && /^(Next|Sign in|Confirm and continue|Allow access)$/i.test(e.innerText.trim()));
  if (!b) return false;
  b.click();
  return true;
})()`;

const isDirectoryConfig = (value: unknown): value is DirectoryConfig =>
  typeof value === "object" &&
  value !== null &&
  fields.every((field) => {
    const command = (value as Record<string, unknown>)[field];
    return Array.isArray(command) && command.length > 0 && command.every((part) => typeof part === "string");
  });

@Injectable({ providedIn: "root" })
export class SsoAutofillService {
  constructor(
    private nativeService: AppNativeService,
    private toasterService: MessageToasterService,
  ) {}

  /**
   * Watches the verification window until the page shows the request as approved, filling in the
   * sign-in steps on the way when credentials are configured. Resolves true on approval, false when
   * the window goes away or time runs out. Approval is read from the page because AWS's current
   * sign-in flow approves the request without the associate_token call Leapp otherwise waits for.
   */
  async watch(webContents: VerificationWebContents): Promise<boolean> {
    const config = this.readConfig();
    let autofill = config !== null;
    const submitted = new Set<Step>();
    let directory: string | null = null;
    let pending: { step: Step; since: number } | null = null;
    const deadline = Date.now() + watchTimeoutMs;

    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, pollMs));
      if (webContents.isDestroyed()) {
        return false;
      }

      let state: PageState;
      try {
        state = (await webContents.executeJavaScript(detectStep)) as PageState; // produced by detectStep above
      } catch {
        continue; // page is navigating
      }
      directory = state.directory ?? directory;
      if (state.step === "approved") {
        return true;
      }
      if (!autofill) {
        continue;
      }

      if (pending) {
        if (state.step !== pending.step && state.step !== "wait") {
          pending = null;
        } else if (Date.now() - pending.since > stepTimeoutMs) {
          autofill = this.stop(`the ${pending.step} step was not accepted`);
          continue;
        } else {
          continue;
        }
      }
      if (state.step === "wait" || !directory) {
        continue;
      }

      const directoryConfig = config?.[directory];
      if (!directoryConfig) {
        autofill = false; // no credentials configured for this Identity Center directory
        continue;
      }
      if (submitted.has(state.step)) {
        autofill = this.stop(`the ${state.step} step came back after it was submitted`);
        continue;
      }

      try {
        await this.submit(webContents, state.step, directoryConfig);
      } catch (error) {
        autofill = this.stop(error instanceof Error ? error.message : String(error));
        continue;
      }
      submitted.add(state.step);
      pending = { step: state.step, since: Date.now() };
    }
    return false;
  }

  private async submit(webContents: VerificationWebContents, step: Step, directoryConfig: DirectoryConfig): Promise<void> {
    const input = stepField[step];
    if (input) {
      if (input.field === "otp") {
        await this.waitForFreshOtpWindow();
      }
      const value = await this.runCommand(directoryConfig[input.field], input.field);
      if ((await webContents.executeJavaScript(focusInput(input.selector))) !== true) {
        throw new Error(`no ${input.field} field on the page`);
      }
      await webContents.insertText(value);
    }
    if ((await webContents.executeJavaScript(clickSubmit)) !== true) {
      throw new Error(`no submit button on the ${step} page`);
    }
  }

  // A TOTP code read in the last seconds of its 30-second window can expire before AWS checks it.
  private async waitForFreshOtpWindow(): Promise<void> {
    const secondsIntoWindow = Math.floor(Date.now() / 1000) % 30;
    if (secondsIntoWindow >= 27) {
      await new Promise((resolve) => setTimeout(resolve, (30 - secondsIntoWindow) * 1000 + 500));
    }
  }

  private runCommand(command: string[], field: Field): Promise<string> {
    const [program, ...args] = command;
    const file = program.startsWith("~/") ? this.nativeService.path.join(this.nativeService.os.homedir(), program.slice(2)) : program;
    return new Promise((resolve, reject) => {
      this.nativeService.execFile(file, args, { timeout: commandTimeoutMs }, (error, stdout) => {
        const value = String(stdout).trim();
        if (error || !value) {
          // Never include stdout: it may hold part of the secret.
          reject(new Error(`the ${field} command failed (${this.nativeService.path.basename(file)})`));
        } else {
          resolve(value);
        }
      });
    });
  }

  private readConfig(): AutofillConfig | null {
    const file = this.nativeService.path.join(this.nativeService.os.homedir(), configFile);
    if (!this.nativeService.fs.existsSync(file)) {
      return null;
    }
    try {
      const parsed: unknown = JSON.parse(this.nativeService.fs.readFileSync(file, "utf8"));
      if (typeof parsed !== "object" || parsed === null) {
        throw new Error("expected an object of directory ids");
      }
      const entries = Object.entries(parsed);
      const invalid = entries.find(([, value]) => !isDirectoryConfig(value));
      if (invalid) {
        throw new Error(`${invalid[0]} needs username, password and otp commands`);
      }
      return Object.fromEntries(entries) as AutofillConfig;
    } catch (error) {
      this.toasterService.toast(`Ignoring ~/${configFile}: ${error instanceof Error ? error.message : error}`, ToastLevel.error, "SSO auto-fill");
      return null;
    }
  }

  // Turns filling off; returns false so callers can write `autofill = this.stop(...)`.
  private stop(reason: string): false {
    this.toasterService.toast(`Stopped: ${reason}. Finish signing in in the window.`, ToastLevel.warn, "SSO auto-fill");
    return false;
  }
}
