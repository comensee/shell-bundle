<?php

namespace Comensee\TracebackBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class DefaultController extends Controller
{
    public function indexAction($name)
    {
        return $this->render('ComenseeTracebackBundle:Default:index.html.twig', array('name' => $name));
    }
}
