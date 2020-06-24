import { GlobalService } from "../global/global.service";
import { Injectable } from "@angular/core";
import {
  HttpInterceptor,
  HttpErrorResponse,
  HttpHandler,
  HttpEvent,
  HttpRequest,
  HttpResponse,
} from "@angular/common/http";
import { Observable, throwError } from "rxjs";
import { catchError, finalize, map } from "rxjs/operators";
import { MDBSpinningPreloader, ToastService } from "ng-uikit-pro-standard";
import { Router } from "@angular/router";

@Injectable({
  providedIn: "root",
})
export class HttpInterceptorService implements HttpInterceptor {
  constructor(
    private globalService: GlobalService,
    private toast: ToastService,
    private router: Router
  ) {}

  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const options = { opacity: 1 };
    this.toast.clear();
    this.globalService.showLoadingSpinner();
    return next.handle(req).pipe(
      map((event: HttpEvent<any>) => {
        if (event instanceof HttpResponse) {
          // console.log('event--->>>', event);
          if (event.body.message != null) {
            if (event.body.indicator === "success") {
              this.toast.success(event.body.message, "INFO", options);
            } else {
              this.toast.error(event.body.message, "ERROR", options);
            }
          }
          if (event.body.redirecturl) {
            this.router.navigate([event.body.redirecturl]);
          }
        }
        return event;
      }),
      catchError((error) => {
        // console.log('error--->>>', error);
        // if (error.status <= 0) {
        //   this.router.navigate(["/maintenance"]);
        // } else if (error.status === 401) {
        //   this.router.navigate(["/login"]);
        // } else {
        //   console.log(error);
        //   this.toast.error(error.error.message, "ERROR", options);
        //   //this.router.navigate([error.error.redirecturl]);
        // }
        return throwError(error);
      }),
      finalize(() => this.globalService.hideLoadingSpinner())
    );
  }
}
