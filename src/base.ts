import fetch from 'node-fetch'

class AuthenticationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AuthenticationError'
  }
}

export abstract class SpondBase {
  private _username: string
  private _password: string
  private _api_url: string
  private _token: string | null
  private _session: typeof fetch

  constructor(username: string, password: string, api_url: string) {
    this._username = username
    this._password = password
    this._api_url = api_url
    this._token = null
    this._session = fetch
  }

  get username(): string {
    return this._username
  }

  set username(value: string) {
    this._username = value
  }

  get password(): string {
    return this._password
  }

  set password(value: string) {
    this._password = value
  }

  get apiUrl(): string {
    return this._api_url
  }

  set apiUrl(value: string) {
    this._api_url = value
  }

  get token(): string | null {
    return this._token
  }

  set token(value: string | null) {
    this._token = value
  }

  get authHeaders(): { [key: string]: string } {
    return {
      'content-type': 'application/json',
      'Authorization': `Bearer ${this.token}`
    }
  }

  static requireAuthentication(target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value

    descriptor.value = async function(this: SpondBase, ...args: any[]) {
      if (!this.token) {
        try {
          await this.login()
        } catch (e) {
          throw e
        }
      }
      return await originalMethod.apply(this, args)
    }

    return descriptor
  }

  async login(): Promise<void> {
    const login_url = `${this.apiUrl}login`
    const data = { email: this.username, password: this.password }

    const response = await this._session(login_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })

    const login_result: any = await response.json()
    this.token = login_result.loginToken

    if (!this.token) {
      throw new AuthenticationError(`Login failed. Response received: ${JSON.stringify(login_result)}`)
    }
  }
}
