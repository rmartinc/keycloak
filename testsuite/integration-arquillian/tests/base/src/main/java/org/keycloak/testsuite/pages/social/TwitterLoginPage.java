/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.testsuite.pages.social;

import org.keycloak.testsuite.util.WaitUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebElement;

/**
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
public class TwitterLoginPage extends AbstractSocialLoginPage {

    @Override
    public void login(String user, String password) {
        // twitter presents a consent page for the application
        // the SignIn button should be clicked first to go to the real login
        By by = By.xpath("//input[@type='submit' and @value='Sign In']");
        WaitUtils.waitUntilElement(by).is().present();
        WebElement element = driver.findElement(by);
        element.click();

        // new login page is two phase login (username and then password) and it
        // needs lots of JS, twitter does not work with default HtmlUnit driver
        by = By.xpath("//input[@type='text' and @name='text']");
        WaitUtils.waitUntilElement(by).is().present();
        element = driver.findElement(by);
        element.clear();
        element.sendKeys(user);
        element.sendKeys(Keys.RETURN);

        // wait for the password input to appear
        by = By.xpath("//input[@type='password']");
        WaitUtils.waitUntilElement(by).is().present();
        element = driver.findElement(by);
        element.clear();
        element.sendKeys(password);
        element.sendKeys(Keys.RETURN);
    }
}
