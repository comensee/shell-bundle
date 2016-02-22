<?php

namespace Comensee\ShellBundle\Tests\Command;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase as BaseKernelTestCase;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ShellCommandTest extends BaseKernelTestCase
{
    /** @var KernelInterface */
    protected $httpKernel;
    /** @var ContainerBuilder */
    protected $container;

    /**
     * @return KernelInterface
     */
    public function getKernel()
    {
        if (null === $this->httpKernel) {
            $this->httpKernel = self::createKernel();
            $this->httpKernel->boot();
            $this->container = $this->httpKernel->getContainer();
        }
        return $this->httpKernel;
    }
    /**
     * @return \Symfony\Component\DependencyInjection\ContainerInterface
     */
    public function getContainer()
    {
        return $this->getKernel()->getContainer();
    }

    /**
     * @group command
     */
    public function testCanRetrieveInstanceOfCommand()
    {
        $command = $this->getContainer()->get('comensee.command.shell');
        $this->assertInstanceOf('Comensee\ShellBundle\Command\ShellCommand', $command);
    }
}
