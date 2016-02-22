<?php

namespace Comensee\ShellBundle\Command;

use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;


class ShellCommand extends ContainerAwareCommand
{
    protected $shellName;
    protected $delimiter;

    public function __construct($shellName, $delimiter)
    {
        $this->shellName = $shellName;
        $this->delimiter = $delimiter;
        parent::__construct();
    }

    protected function configure()
    {
        $this
            ->setname( 'shell:start' )
            ->setDescription( 'Start a shell')
            ;
    }

    public function execute( InputInterface $input, OutputInterface $output )
    {
        $boris = new \Boris\Boris(sprintf('%s%s ', $this->shellName, $this->delimiter));
        $boris->setLocal(array('container' => $this->getContainer()));
        $boris->start();
    }

}


