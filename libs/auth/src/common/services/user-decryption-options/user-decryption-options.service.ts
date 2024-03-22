import { map } from "rxjs";

import {
  ActiveUserState,
  StateProvider,
  USER_DECRYPTION_OPTIONS_DISK,
  UserKeyDefinition,
} from "@bitwarden/common/platform/state";
import { UserId } from "@bitwarden/common/src/types/guid";

import { InternalUserDecryptionOptionsServiceAbstraction } from "../../abstractions/user-decryption-options.service.abstraction";
import { UserDecryptionOptions } from "../../models";

export const USER_DECRYPTION_OPTIONS = new UserKeyDefinition<UserDecryptionOptions>(
  USER_DECRYPTION_OPTIONS_DISK,
  "decryptionOptions",
  {
    deserializer: (decryptionOptions) => UserDecryptionOptions.fromJSON(decryptionOptions),
    clearOn: ["logout"],
  },
);

export class UserDecryptionOptionsService
  implements InternalUserDecryptionOptionsServiceAbstraction
{
  private userDecryptionOptionsState: ActiveUserState<UserDecryptionOptions>;

  userDecryptionOptions$;
  hasMasterPassword$;

  constructor(private stateProvider: StateProvider) {
    this.userDecryptionOptionsState = this.stateProvider.getActive(USER_DECRYPTION_OPTIONS);

    this.userDecryptionOptions$ = this.userDecryptionOptionsState.state$;
    this.hasMasterPassword$ = this.userDecryptionOptions$.pipe(
      map((options) => options?.hasMasterPassword ?? false),
    );
  }

  userDecryptionOptionsById$(userId: UserId) {
    return this.stateProvider.getUser(userId, USER_DECRYPTION_OPTIONS).state$;
  }

  async setUserDecryptionOptions(userDecryptionOptions: UserDecryptionOptions): Promise<void> {
    await this.userDecryptionOptionsState.update((_) => userDecryptionOptions);
  }
}
