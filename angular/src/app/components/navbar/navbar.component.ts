import { Component, OnInit, ViewChild } from '@angular/core';
import { ModalDirective, ToastService, MDBSpinningPreloader } from 'ng-uikit-pro-standard';
import { Router, NavigationStart } from '@angular/router';
import { LoginService } from 'src/app/api/login/login.service';
import { CookieService } from 'ngx-cookie-service';
import { GlobalService } from 'src/app/service/global/global.service';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements OnInit {

  @ViewChild('login', { static: true }) login: ModalDirective;
  @ViewChild('signup', { static: true }) signup: ModalDirective;
  @ViewChild('sidenav', { static: true }) public sidenav: any;
  @ViewChild('forgotPassword', { static: true }) public forgotPassword: any;
  @ViewChild('resetPassword', { static: true }) public resetPassword: any;

  loggedIn: boolean;
  check: boolean = false;
  username = '';
  password = '';
  passwordNew = '';
  email = '';
  username_validation_message = '';
  rememberme = false;

  constructor(
    private mdbSpinningPreloader: MDBSpinningPreloader,
    private loginService: LoginService,
    private globalService: GlobalService,
    private toast: ToastService,
    private cookie: CookieService,
    private router: Router
  ) {
    this.globalService.login_Cast.subscribe(
      (login) => (this.loggedIn = login)
    );
  }

  ngOnInit() {
    this.router.events.subscribe((val) => {
      if (val instanceof NavigationStart) {
        this.sidenav.hide();
      }
    });

    if (this.cookie.check('token')) {
      this.globalService.loginUser();
    } else {
      this.globalService.logoutUser();
    }

    if (this.cookie.check('user-name')) {
      this.username = this.cookie.get('user-name');
    }
  }

  //Validation
  checkid() {
    if (this.username.length > 0) {
      return false;
    } else {
      return true;
    }
  }

  checkpass() {
    if (this.password.length > 0) {
      return false;
    } else {
      return true;
    }
  }

  checkpassNew() {
    if (this.passwordNew.length > 0) {
      return false;
    } else {
      return true;
    }
  }

  checkemail() {
    const validation = /^([a-z0-9_\.-]+)@([\da-z\.-]+)\.([a-z\.]{2,6})$/.test(this.email);
    if (this.email.length > 0 && validation) {
      return false;
    } else {
      return true;
    }
  }

  //Show Popup
  showLogin() {
    this.username = '';
    if (this.cookie.check('user')) {
      this.username = this.cookie.get('user');
    }
    this.password = '';
    this.login.show();
  }

  showRegister() {
    this.check = false;
    this.username = '';
    this.password = '';
    this.email = '';
    this.signup.show();
  }

  //API
  userlogin() {
    this.login.hide();
    this.globalService.showLoadingSpinner();
    this.loginService.userLogin(this.username, this.password).subscribe(
      (result) => {
        var d = new Date();
        d.setTime(d.getTime() + (result.expiry * 1000));
        this.cookie.set('token', result.token, d, '/', window.location.hostname, false, 'Strict');
        this.cookie.set('user-name', this.username, d, '/', window.location.hostname, false, 'Strict');
        if (this.rememberme) {
          this.cookie.set('user', this.username, 30, '/', window.location.hostname, false, 'Strict');
        }
        this.login.hide();
        this.globalService.loginUser();
      },
      (err) => {
        this.login.show();
        console.log(err);
        this.toast.error('Login Failed');
      }
    );
    this.globalService.hideLoadingSpinner();
  }

  register() {
    this.globalService.showLoadingSpinner();
    this.signup.hide();
    console.log(this.check + ' check');
    console.log(this.username.length + ' lemgth');
    if (this.check === true && this.username.length > 0) {
      this.loginService.register(this.username, this.password, this.email, 'user').subscribe(
        (result) => {
          this.signup.hide();
        },
        (err) => {
          this.signup.show();
          console.log(err);
          this.toast.error('Error Occured');
        }
      );
    } else {
      this.toast.error('Username is empty');
      this.signup.show();
    }
    this.globalService.hideLoadingSpinner();
  }

  userCheck() {
    this.loginService.checkUsername(this.username).subscribe(
      (result) => {
        this.check = result.check;
        if (result.check === true) {
          this.username_validation_message = 'Username available';
        } else {
          this.username_validation_message = 'Username in use, please try again';
        }
      },
      (err) => {
        console.log(err);
        this.toast.error('Error Occured');
      }
    );
  }

  logout() {
    this.globalService.showLoadingSpinner();
    this.loginService.logout('Bearer ' + this.cookie.get('token')).subscribe(
      (result) => {
        if (result.indicator === 'success') {
          this.cookie.delete('token');
          this.cookie.delete('user-name');
          this.globalService.logoutUser();
        }
      },
      (err) => {
        console.log(err);
      }
    );
    this.globalService.hideLoadingSpinner();
  }

  resetPasswordLoggedIn() {
    this.globalService.showLoadingSpinner();
    this.resetPassword.hide();
    if (this.check === false) {
      this.loginService.resetPassLoggedIn('Bearer ' + this.cookie.get('token'), this.password, this.passwordNew).subscribe(
        (result) => {
        },
        (err) => {
          this.resetPassword.show();
          console.log(err);
          this.toast.error('Error Occured');
        }
      );
    }
    this.globalService.hideLoadingSpinner();
  }

  forgotPass() {
    this.globalService.showLoadingSpinner();
    this.forgotPassword.hide();
    if (this.check === false && this.checkemail() === false) {
      this.loginService.forgotPass(this.username, this.email).subscribe(
        (result) => {
        },
        (err) => {
          this.forgotPassword.show();
          console.log(err);
          this.toast.error('Error Occured');
        }
      );
    } else {
      this.toast.error('Please fill reuired fields');
      this.forgotPassword.show();
    }
    this.globalService.hideLoadingSpinner();
  }

}