import { Injectable, OnInit } from "@angular/core";
import { BehaviorSubject } from "rxjs/internal/BehaviorSubject";

@Injectable({
  providedIn: "root",
})
export class GlobalService {
  private loadingSpinner = new BehaviorSubject<boolean>(false);
  loadingSpinner_Cast = this.loadingSpinner.asObservable();

  private navBar = new BehaviorSubject<boolean>(false);
  navBar_Cast = this.navBar.asObservable();

  private login = new BehaviorSubject<boolean>(false);
  login_Cast = this.login.asObservable();

  constructor() { }

  showLoadingSpinner() {
    this.loadingSpinner.next(true);
  }

  hideLoadingSpinner() {
    this.loadingSpinner.next(false);
  }

  showNavBar() {
    this.navBar.next(true);
  }

  hideNavBar() {
    this.navBar.next(false);
  }

  loginUser() {
    this.login.next(true);
  }

  logoutUser() {
    this.login.next(false);
  }

}
