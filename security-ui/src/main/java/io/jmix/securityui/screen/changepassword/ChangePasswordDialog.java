/*
 * Copyright 2021 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.jmix.securityui.screen.changepassword;

import com.google.common.base.Strings;
import io.jmix.core.Messages;
import io.jmix.core.common.util.Preconditions;
import io.jmix.core.security.PasswordNotMatchException;
import io.jmix.core.security.UserManager;
import io.jmix.ui.Notifications;
import io.jmix.ui.component.*;
import io.jmix.ui.screen.*;
import io.jmix.ui.util.OperationResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;

import javax.annotation.Nullable;
import java.util.EventObject;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

@UiController("ChangePasswordDialog")
@UiDescriptor("change-password-dialog.xml")
public class ChangePasswordDialog extends Screen {

    @Autowired
    protected Messages messages;
    @Autowired
    protected UserManager userManager;
    @Autowired
    protected Notifications notifications;
    @Autowired
    protected ScreenValidation screenValidation;

    @Autowired
    protected PasswordField passwordField;
    @Autowired
    protected PasswordField confirmPasswordField;
    @Autowired
    protected PasswordField currentPasswordField;

    protected UserDetails user;
    protected Consumer<ChangePasswordActionEvent> actionHandler;
    protected Function<ValidationContext, ValidationErrors> validator;

    /**
     * @return user for which should be changed password
     */
    public UserDetails getUser() {
        return user;
    }

    /**
     * Sets user for which should be changed password.
     *
     * @param user user
     * @return current instance of dialog
     */
    public ChangePasswordDialog withUser(UserDetails user) {
        this.user = user;
        return this;
    }

    /**
     * @return action handler or {@code null} if not set
     */
    @Nullable
    public Consumer<ChangePasswordActionEvent> getActionHandler() {
        return actionHandler;
    }

    /**
     * Sets action handler. Its invoked when a user clicks on the {@code OK} or {@code Cancel} buttons.
     * <p>
     * Before firing the event for {@code OK} action, validation is performed.
     *
     * @param actionHandler action handler to set
     * @return current instance of dialog
     */
    public ChangePasswordDialog withActionHandler(@Nullable Consumer<ChangePasswordActionEvent> actionHandler) {
        this.actionHandler = actionHandler;
        return this;
    }

    /**
     * @return {@code true} if a user should enter the current password
     */
    public boolean isCurrentPasswordRequired() {
        return currentPasswordField.isVisible();
    }

    /**
     * Sets whether a user should enter the current password.
     * <p>
     * Default value is {@code false}.
     *
     * @param required required option
     * @return current instance of dialog
     */
    public ChangePasswordDialog withCurrentPasswordRequired(boolean required) {
        currentPasswordField.setVisible(required);
        return this;
    }

    /**
     * @return validator or {@code null} if not set
     */
    @Nullable
    public Function<ValidationContext, ValidationErrors> getValidator() {
        return validator;
    }

    /**
     * Sets validator that should replace the default validation in the dialog.
     *
     * @param validator validator to set
     * @return current instance of dialog
     */
    public ChangePasswordDialog withValidator(@Nullable Function<ValidationContext, ValidationErrors> validator) {
        this.validator = validator;
        return this;
    }

    @Subscribe
    protected void onAfterShow(AfterShowEvent event) {
        Preconditions.checkNotNullArgument(user, "Dialog cannot be opened without user");

        getWindow().setCaption(String.format(
                messages.getMessage("changePasswordDialog.captionWithUserName"), user.getUsername()));
    }

    @Subscribe("okBtn")
    protected void onOkBtnClick(Button.ClickEvent event) {
        if (!validate()) {
            return;
        }

        if (actionHandler != null) {
            actionHandler.accept(new ChangePasswordActionEvent(this, true,
                    getPassword(), getConfirmPassword(), getCurrentPassword()));
            return;
        }

        changePassword(user.getUsername(), getPassword(), getCurrentPassword())
                .then(() -> {
                    notifications.create()
                            .withType(Notifications.NotificationType.HUMANIZED)
                            .withCaption(messages.getMessage("changePasswordDialog.passwordChanged"))
                            .show();
                    close(StandardOutcome.COMMIT);
                }).otherwise(() -> {
                    if (currentPasswordField.isVisible()) {
                        notifications.create()
                                .withType(Notifications.NotificationType.ERROR)
                                .withCaption(messages.getMessage("changePasswordDialog.wrongCurrentPassword"))
                                .show();
                    } else {
                        notifications.create()
                                .withType(Notifications.NotificationType.WARNING)
                                .withCaption(messages.getMessage("changePasswordDialog.currentPasswordWarning"))
                                .show();
                    }
                });
    }

    @Subscribe("cancelBtn")
    protected void onCancelBtnClick(Button.ClickEvent event) {
        if (actionHandler != null) {
            actionHandler.accept(new ChangePasswordActionEvent(this, false,
                    getPassword(), getConfirmPassword(), getCurrentPassword()));
        } else {
            close(StandardOutcome.DISCARD);
        }
    }

    protected boolean validate() {
        ValidationErrors errors = validator != null
                ? validator.apply(
                new ValidationContext(this, getPassword(), getConfirmPassword(), getCurrentPassword()))
                : validatePassword(passwordField, confirmPasswordField, currentPasswordField);

        if (errors.isEmpty()) {
            return true;
        } else {
            screenValidation.showValidationErrors(this, errors);
            return false;
        }
    }

    protected ValidationErrors validatePassword(PasswordField passwordField,
                                                PasswordField confirmPasswordField,
                                                PasswordField currentPasswordField) {
        ValidationErrors errors = new ValidationErrors();

        String password = passwordField.getValue();
        String confirmPassword = confirmPasswordField.getValue();
        String currentPassword = currentPasswordField.getValue();

        if (Strings.isNullOrEmpty(password)) {
            errors.add(passwordField, messages.getMessage("changePasswordDialog.passwordRequired"));
        }
        if (Strings.isNullOrEmpty(confirmPassword)) {
            errors.add(passwordField, messages.getMessage("changePasswordDialog.confirmPasswordRequired"));
        }
        if (!Strings.isNullOrEmpty(password)
                && !Strings.isNullOrEmpty(confirmPassword)
                && !Objects.equals(password, confirmPassword)) {
            errors.add(confirmPasswordField, messages.getMessage("changePasswordDialog.passwordsDoNotMatch"));
        }
        if (currentPasswordField.isVisible()) {
            if (Strings.isNullOrEmpty(currentPassword)) {
                errors.add(passwordField, messages.getMessage("changePasswordDialog.currentPasswordRequired"));
            } else if (Objects.equals(password, currentPassword)) {
                errors.add(passwordField, messages.getMessage("changePasswordDialog.currentPasswordWarning"));
            }
        }

        if (errors.isEmpty()) {
            return ValidationErrors.none();
        }
        return errors;
    }

    protected OperationResult changePassword(String username, String password, @Nullable String currentPassword) {
        try {
            userManager.changePassword(username, currentPassword, password);
        } catch (PasswordNotMatchException e) {
            return OperationResult.fail();
        }
        return OperationResult.success();
    }

    @Nullable
    protected String getPassword() {
        return passwordField.getValue();
    }

    @Nullable
    protected String getConfirmPassword() {
        return confirmPasswordField.getValue();
    }

    @Nullable
    protected String getCurrentPassword() {
        return currentPasswordField.getValue();
    }

    /**
     * Class describes user's click on buttons ({@code OK}, {@code Cancel}).
     */
    public static class ChangePasswordActionEvent extends EventObject {

        protected Boolean confirmed;

        protected String password;
        protected String confirmPassword;
        protected String currentPassword;

        public ChangePasswordActionEvent(ChangePasswordDialog source, Boolean confirmed,
                                         String password, String confirmPassword, String currentPassword) {
            super(source);
            this.confirmed = confirmed;
            this.password = password;
            this.confirmPassword = confirmPassword;
            this.currentPassword = currentPassword;
        }

        @Override
        public ChangePasswordDialog getSource() {
            return (ChangePasswordDialog) super.getSource();
        }

        /**
         * @return {@code true} if {@code OK} button is clicked
         */
        public boolean isOk() {
            return Boolean.TRUE.equals(confirmed);
        }

        /**
         * @return password value
         */
        @Nullable
        public String getPassword() {
            return password;
        }

        /**
         * @return confirm password value
         */
        @Nullable
        public String getConfirmPassword() {
            return confirmPassword;
        }

        /**
         * @return current password value
         */
        @Nullable
        public String getCurrentPassword() {
            return currentPassword;
        }
    }

    /**
     * Describes validation context for change password dialog.
     */
    public static class ValidationContext {

        protected ChangePasswordDialog source;

        protected String password;
        protected String confirmPassword;
        protected String currentPassword;

        public ValidationContext(ChangePasswordDialog source, String password, String confirmPassword,
                                 String currentPassword) {
            this.source = source;
            this.password = password;
            this.confirmPassword = confirmPassword;
            this.currentPassword = currentPassword;
        }

        /**
         * @return change password dialog
         */
        public ChangePasswordDialog getSource() {
            return source;
        }

        /**
         * @return password value
         */
        @Nullable
        public String getPassword() {
            return password;
        }

        /**
         * @return confirm password value
         */
        @Nullable
        public String getConfirmPassword() {
            return confirmPassword;
        }

        /**
         * @return current password value
         */
        @Nullable
        public String getCurrentPassword() {
            return currentPassword;
        }
    }
}
