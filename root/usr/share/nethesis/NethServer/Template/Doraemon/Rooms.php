<?php

/* @var $view \Nethgui\Renderer\Xhtml */
$view->requireFlag($view::INSET_FORM);

if ($view->getModule()->getIdentifier() == 'update') {
    // disable updating of hostname
    // the hostname is the key of the db item, if you change it, bad things happens
    $keyFlags = $view::STATE_DISABLED;
    $template = 'Update_Room_Header';
} else {
    $keyFlags = 0;
    $template = 'Create_Room_Header';
}

echo $view->header('doraemon')->setAttribute('template', $view->translate($template));

echo $view->panel()
    ->insert($view->textInput('ibay', $keyFlags))
    ->insert($view->textInput('Description'))
    ->insert($view->selector('OwningGroup', $view::SELECTOR_DROPDOWN))
    ->insert($view->checkBox('GroupAccess', 'rw')->setAttribute('uncheckedValue', 'r'))
    ->insert($view->checkBox('OtherAccess', 'r')->setAttribute('uncheckedValue', ''))
    ->insert($view->objectPicker()
    ->setAttribute('objects', 'AclSubjects')
    ->setAttribute('objectLabel', 1)
    ->insert($view->checkBox('AclRead', FALSE, $view::STATE_CHECKED))
    ->insert($view->checkBox('AclWrite', FALSE))
);

echo $view->buttonList($view::BUTTON_SUBMIT | $view::BUTTON_CANCEL | $view::BUTTON_HELP);

$actionId = $view->getUniqueId();
$view->includeJavascript("
jQuery(function($){
    $('#${actionId}').on('nethguishow', function () {
        $(this).find('.Tabs').tabs('select', 0);
    });
});
");
