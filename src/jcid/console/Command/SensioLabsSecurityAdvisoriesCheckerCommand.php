<?php

namespace jcid\console\Command;

use GuzzleHttp\Client;
use GuzzleHttp\Post\PostFile;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\Question;

/**
 * Class SensioLabsSecurityAdvisoriesCheckerCommand
 */
class SensioLabsSecurityAdvisoriesCheckerCommand extends Command
{
    /**
     *
     */
    protected function configure()
    {
        $this
            ->setName('gitlab:sensiolabs-security-advisories-checker')
            ->setDescription('Gitlab integration with SensioLabs Security Advisories Checker');
    }

    /**
     * @param InputInterface $input
     * @param OutputInterface $output
     *
     * @return int|null|void
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $helper = $this->getHelper('question');

        // Ask Gitlab API url
        $gitlibApiUrlQuestion = new Question(
            'Please fill in the Gitlab API url, example https://gitlab.comnl/api/v3/: '
        );
        $gitlabApiUrl         = $helper->ask($input, $output, $gitlibApiUrlQuestion);

        // Ask Gitlab API token
        $gitlibApiTokenQuestion = new Question(
            'Please fill in the Gitlab API token: '
        );
        $gitlabApiToken         = $helper->ask($input, $output, $gitlibApiTokenQuestion);

        // Waiting feedback
        $output->writeln('Please wait, the Gitlab projects are checked against the SensioLabs Security Advisories..');

        // SensioLabs Security Advisories client
        $seniolabsSecurityCheckerClient = new Client(
            [
                'base_url' => 'https://security.sensiolabs.org/',
            ]
        );

        // Gitlab client
        $gitlabClient = new Client(
            [
                'base_url' => $gitlabApiUrl,
                'defaults' => [
                    'verify' => false,
                    'query'  => [
                        'private_token' => $gitlabApiToken,
                    ]
                ],
            ]
        );

        // Get all Gitlab projects
        $projecten = $gitlabClient->get(
            'projects/all',
            [
                'query' => [
                    'archived' => 'false',
                    'order_by' => 'updated_at',
                    'sort'     => 'asc',
                    'per_page' => 100, // http://doc.gitlab.com/ce/api/
                ]
            ]
        )->json();

        // Loop through Gitlab repositories
        $rows = null;
        foreach ($projecten as $project) {

            // Try the production, develop and master branch
            foreach (['production', 'develop', 'master'] as $branch) {
                $fileResponse = $gitlabClient->get(
                    'projects/' . $project['id'] . '/repository/files',
                    [
                        'exceptions' => false,
                        'query'      => [
                            'file_path' => 'composer.lock',
                            'ref'       => $branch,
                        ]
                    ]
                );

                // Only continue when we found the composer.lock
                if ($fileResponse->getStatusCode() === 200) {

                    // Get composer.lock content
                    $content = $fileResponse->json();
                    $content = base64_decode($content['content']);

                    // Check the composer.lock against the SensioLabs Security Advisories Checker
                    $checkResponse = $seniolabsSecurityCheckerClient->post(
                        'check_lock',
                        [
                            'headers' => [
                                'Accept' => 'application/json',
                            ],
                            'body'    => [
                                'lock' => new PostFile('lock', $content)
                            ]
                        ]
                    );

                    // SensioLabs Security Advisories Checker packages doorlopen
                    $packages = $checkResponse->json();
                    foreach ($packages as $package => $advisories) {
                        foreach ($advisories['advisories'] as $advisorieKey => $advisorieInfo) {
                            $rows[] = [
                                $project['name_with_namespace'],
                                $advisorieInfo['cve'],
                                $package,
                                $advisories['version'],
                                $advisorieKey,
                                $advisorieInfo['title'],
                                $advisorieInfo['link'],
                            ];
                        }
                    }

                    // Security issues were found in the first branch, so we can ignore the other branches.
                    break;
                }
            }
        }

        // Output
        if (is_array($rows)) {
            $table = new Table($output);
            $table->setHeaders(['Project', 'CVE', 'Packages', 'Versie', 'CVE unique key', 'CVE titel', 'CVE link']);
            $table->setRows($rows);
            $table->render();
        }
    }
}
