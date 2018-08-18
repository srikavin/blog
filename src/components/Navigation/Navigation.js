import React from 'react';
import {
    Alignment,
    Button,
    Menu,
    MenuItem,
    Navbar,
    NavbarDivider,
    NavbarGroup,
    NavbarHeading,
    Popover,
    Position
} from '@blueprintjs/core';
import {IconNames} from '@blueprintjs/icons';
import NavLink from './NavLink/NavLink';
import {Auth} from '../../data/resource/auth';
import Link from 'react-router-dom/es/Link';
import {FaGithub} from 'react-icons/fa';
import './Navigation.css'

class Navigation extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            auth: Auth,
            user: {}
        };
        this.updateUser = this.updateUser.bind(this);
    }

    componentDidMount() {
        Auth.onChange(this.updateUser);
        Auth.getUser().then(e => {
            this.setState({
                user: e
            });
        });
    }

    updateUser(user) {
        console.log(user);
        this.setState({user});
    }

    redirect(url) {
        return () => {
            window.open(url, '_blank')
        }
    }

    render() {
        return (
            <Navbar>
                <NavbarGroup align={Alignment.LEFT}>
                    <NavbarHeading>
                        <Link to={'/'}>Srikavin Ramkumar</Link>
                    </NavbarHeading>
                    <NavbarDivider/>
                    <NavLink to="/" icon={IconNames.LAYOUT_AUTO} label="About"/>
                    <NavLink to="/blog" icon={IconNames.CODE} label="Blog"/>
                </NavbarGroup>
                <NavbarGroup align={Alignment.RIGHT}>
                    {this.state.auth.isLoggedIn() ? (
                        <>
                            <NavLink icon={'control'} to="/admin" label="Admin"/>
                            <NavbarDivider/>
                            <Popover content={<Menu>
                                <MenuItem text="Profile" icon="user"/>
                                <MenuItem onClick={this.state.auth.logout} text="Logout" icon="log-out"/>
                            </Menu>} position={Position.BOTTOM}>
                                <Button icon="user" text={this.state.user.username}/>
                            </Popover>
                        </>
                    ) : (
                        <div className={'externalIcons'}>
                            <FaGithub className={'navExternIconLink'}
                                      onClick={this.redirect('https://github.com/srikavin')} size={25}/>&nbsp;
                        </div>
                    )}
                </NavbarGroup>
            </Navbar>
        )
    }
}

export default Navigation;