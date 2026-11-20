import { constants } from "@noovolari/leapp-core/models/constants";
import { Injectable } from "@angular/core";
import {
  RegisterClientResponse,
  StartDeviceAuthorizationResponse,
  VerificationResponse,
} from "@noovolari/leapp-core/services/session/aws/aws-sso-role-service";
import { IAwsSsoOidcVerificationWindowService } from "@noovolari/leapp-core/interfaces/i-aws-sso-oidc-verification-window-service";
import { WindowService } from "./window.service";
import { MessageToasterService, ToastLevel } from "./message-toaster.service";
import { AppProviderService } from "./app-provider.service";
import { SsoAutofillService } from "./sso-autofill.service";

@Injectable({ providedIn: "root" })
export class AppVerificationWindowService implements IAwsSsoOidcVerificationWindowService {
  constructor(
    private windowService: WindowService,
    private toasterService: MessageToasterService,
    private appProviderService: AppProviderService,
    private ssoAutofillService: SsoAutofillService
  ) {}

  async openVerificationWindow(
    registerClientResponse: RegisterClientResponse,
    startDeviceAuthorizationResponse: StartDeviceAuthorizationResponse,
    windowModality: string,
    onWindowClose: () => void
  ): Promise<VerificationResponse> {
    if (startDeviceAuthorizationResponse.verificationUriComplete.indexOf("?user_code=") > -1) {
      const code = startDeviceAuthorizationResponse.verificationUriComplete.split("?user_code=")[1];
      this.windowService.authorizationDialog(code);
    }

    const openWindowInApp = constants.inApp.toString();

    if (startDeviceAuthorizationResponse.verificationUriComplete.indexOf("?user_code=") > -1) {
      const code = startDeviceAuthorizationResponse.verificationUriComplete.split("?user_code=")[1];
      this.toasterService.toast(`Your AWS user code for this SSO request is: ${code}`, ToastLevel.info, "SSO Security Code");
    }

    if (windowModality === openWindowInApp) {
      return this.openVerificationBrowserWindow(registerClientResponse, startDeviceAuthorizationResponse, onWindowClose);
    } else {
      return this.openExternalVerificationBrowserWindow(registerClientResponse, startDeviceAuthorizationResponse);
    }
  }

  private async openVerificationBrowserWindow(
    registerClientResponse: RegisterClientResponse,
    startDeviceAuthorizationResponse: StartDeviceAuthorizationResponse,
    onWindowClose: () => void
  ): Promise<VerificationResponse> {
    const parentWindowPosition = this.windowService.getCurrentWindow().getPosition();
    const verificationWindow = this.windowService.newWindow(
      startDeviceAuthorizationResponse.verificationUriComplete,
      true,
      "Portal url - Client verification",
      parentWindowPosition[0] + 200,
      parentWindowPosition[1] + 50
    );

    verificationWindow.loadURL(startDeviceAuthorizationResponse.verificationUriComplete);
    verificationWindow.on("close", (e) => {
      e.preventDefault();
      onWindowClose();
    });

    return new Promise((resolve, reject) => {
      let approved = false;
      // Once the code is verified and the user is logged in, drop the window and let core fetch the token.
      // destroy() rather than close(): the "close" handler above is the user-cancelled path, which makes the
      // caller stop every AWS SSO session.
      const approve = () => {
        if (approved) {
          return;
        }
        approved = true;
        verificationWindow.destroy();
        resolve({
          clientId: registerClientResponse.clientId,
          clientSecret: registerClientResponse.clientSecret,
          deviceCode: startDeviceAuthorizationResponse.deviceCode,
        });
      };
      this.ssoAutofillService.watch(verificationWindow.webContents).then((pageApproved) => pageApproved && approve());

      verificationWindow.webContents.session.webRequest.onCompleted(
        {
          urls: this.getAssociateTokenUrls(),
        },
        (details, callback) => {
          if (details.method === "POST" && details.statusCode === 200) {
            approve();
          }

          callback({
            requestHeaders: details.requestHeaders,
            url: details.url,
          });
        }
      );

      verificationWindow.webContents.session.webRequest.onErrorOccurred((details) => {
        if (
          details.error.indexOf("net::ERR_ABORTED") < 0 &&
          details.error.indexOf("net::ERR_FAILED") < 0 &&
          details.error.indexOf("net::ERR_CACHE_MISS") < 0 &&
          details.error.indexOf("net::ERR_CONNECTION_REFUSED") < 0
        ) {
          if (verificationWindow) {
            verificationWindow.close();
          }
          reject(details.error.toString());
        }
      });
    });
  }

  private getAssociateTokenUrls() {
    return this.appProviderService.awsCoreService
      .getRegions()
      .map((region) => `https://oidc.${region.region}.amazonaws.com/device_authorization/associate_token`);
  }

  private async openExternalVerificationBrowserWindow(
    registerClientResponse: RegisterClientResponse,
    startDeviceAuthorizationResponse: StartDeviceAuthorizationResponse
  ): Promise<VerificationResponse> {
    const uriComplete = startDeviceAuthorizationResponse.verificationUriComplete;
    return new Promise((resolve) => {
      // Open external browser window and let authentication begins
      this.windowService.openExternalUrl(uriComplete);

      // Return the code to be used after
      const verificationResponse: VerificationResponse = {
        clientId: registerClientResponse.clientId,
        clientSecret: registerClientResponse.clientSecret,
        deviceCode: startDeviceAuthorizationResponse.deviceCode,
      };

      resolve(verificationResponse);
    });
  }
}
