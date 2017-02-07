<?php
/* @var $view \Nethgui\Renderer\Xhtml */

if ($view->getModule()->getIdentifier() == 'update') {
    // disable updating of hostname
    // the hostname is the key of the db item, if you change it, bad things happens
    $keyFlags = $view::STATE_DISABLED;
    $template = 'Update_Host_Header';
} else {
    $keyFlags = 0;
    $template = 'Create_Host_Header';
}

echo $view->header('hostname')->setAttribute('template', $T($template));

echo $view->panel()
        ->insert($view->textInput('hostname', $keyFlags))
        ->insert($view->textInput('MacAddress'))
        ->insert($view->textInput('Role'))
;
        
echo $view->buttonList($view::BUTTON_SUBMIT | $view::BUTTON_CANCEL | $view::BUTTON_HELP);
