/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package org.mitre.openid.connect.config;

import java.util.Set;

/**
 *
 * Bean for UI (front-end) configuration to be read at start-up.
 *
 * @author jricher
 *
 */
public class UIConfiguration {

  private Set<String> jsFiles;

  /**
   * @return the jsFiles
   */
  public Set<String> getJsFiles() {
    return jsFiles;
  }

  /**
   * @param jsFiles the jsFiles to set
   */
  public void setJsFiles(Set<String> jsFiles) {
    this.jsFiles = jsFiles;
  }

}
