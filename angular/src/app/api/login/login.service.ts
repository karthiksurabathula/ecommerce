import { Injectable } from '@angular/core';
import { GlobalVariables } from 'src/app/globalVariables';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { LoginResponse } from 'src/app/model/loginResponse';

@Injectable({
  providedIn: 'root'
})
export class LoginService {

  url: string = GlobalVariables.baseURL;

  constructor(private http: HttpClient) { }

  public userLogin(username: string, password: string) {
    let user = {
      username: username,
      password: password,
    };

    return this.http.post<LoginResponse>(this.url + 'login-service/authenticate', user, {
      headers: new HttpHeaders().set('Content-Type', 'application/json'),
    });
  }

  public register(username: string, password: string, email: string, role: string) {
    let user = {
      username: username,
      password: password,
      email: email,
      role: role
    };

    return this.http.post<LoginResponse>(this.url + 'login-service/register', user, {
      headers: new HttpHeaders().set('Content-Type', 'application/json'),
    });
  }

  public checkUsername(username: string) {
    let params = new HttpParams();
    params = params.append("username", username);

    return this.http.post<any>(this.url + 'login-service/check', {}, {
      headers: new HttpHeaders().set('Content-Type', 'application/json'), params,
    });
  }

  public logout(bearer: string) {
    return this.http.post<LoginResponse>(
      this.url + "login-service/api/logout",
      {},
      {
        headers: new HttpHeaders().set("Authorization", bearer),
      }
    );
  }

  public resetPassLoggedIn(
    bearer: string,
    currentPassword: string,
    password: string,
  ) {
    let resetReq = {
      currentPassword: currentPassword,
      password: password
    };

    return this.http.post<LoginResponse>(this.url + "login-service/api/reset", resetReq, {
      headers: new HttpHeaders()
        .set("Content-Type", "application/json")
        .set("Authorization", bearer),
    });
  }

  public forgotPass(username: string, email: string) {
    let user = {
      username: username,
      email: email
    };
    return this.http.post<LoginResponse>(this.url + 'login-service/reset', user, {
      headers: new HttpHeaders().set('Content-Type', 'application/json'),
    });
  }
}
