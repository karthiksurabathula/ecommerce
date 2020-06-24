import { Component, OnInit, AfterViewChecked, ChangeDetectorRef } from '@angular/core';
import { MDBSpinningPreloader } from 'ng-uikit-pro-standard';
import { GlobalService } from './service/global/global.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit, AfterViewChecked {
  loadingSpinner: boolean;
  showNavBar: boolean;

  constructor(
    private mdbSpinningPreloader: MDBSpinningPreloader,
    private globalService: GlobalService,
    private cdr: ChangeDetectorRef
  ) {
    this.globalService.loadingSpinner_Cast.subscribe(
      (loadingSpinner) => (this.loadingSpinner = loadingSpinner)
    );
    this.globalService.navBar_Cast.subscribe(
      (showNavBar) => (this.showNavBar = showNavBar)
    );
  }

  ngOnInit() {
    this.mdbSpinningPreloader.stop();
    this.globalService.showNavBar();
  }

  ngAfterViewChecked() {
    this.cdr.detectChanges();
  }
}
