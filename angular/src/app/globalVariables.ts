import { HttpClient } from "@angular/common/http";
import { Location } from "@angular/common";
import { Injectable, Inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

export class GlobalVariables {

  constructor() {}

  public static get baseURL(): string {
    return (
      // window.location.protocol + "//" + window.location.hostname + ":" + window.location.port + "/"
      window.location.protocol + "//" + window.location.hostname + ":" + 8082 + "/"
    );
  }
}
