import React from 'react';

import {css, StyleSheet} from 'aphrodite';
import PostEditor from '../PostEditor';
import RequireAuth from '../../Auth/RequireAuth/RequireAuth';
import {Redirect} from 'react-router-dom';
import {PostStore} from '../../../data/resource/post';
import {Auth} from '../../../data/resource/auth';
import {Intent, Position, Toast, Toaster} from '@blueprintjs/core';
import {IconNames} from '@blueprintjs/icons';

const EditorToaster = Toaster.create({
    className: 'recipe-toaster',
    position: Position.TOP
});

class Editor extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            loading: true,
            toasts: [],
            post: {
                id: '',
                title: '',
                contents: '',
                slug: '',
                tags: []
            }
        };

        this.toaster = React.createRef();

        this.onSubmit = this.onSubmit.bind(this);
        this.onSubmitDraft = this.onSubmitDraft.bind(this)
    }

    componentDidMount() {
        Auth.getUser().then(user => {
            this.setState({
                loading: false,
                post: {
                    ...this.state.post,
                    author: user
                }
            });
        });
    }

    onSubmit(postObj) {
        PostStore.createPost({
            ...postObj
        }).then((e) => {
            EditorToaster.show({
                message: 'Updated successfully',
                intent: Intent.SUCCESS,
                icon: IconNames.TICK,
                action: {
                    target: '_blank',
                    href: `/posts/${e.slug}`,
                    text: 'View Post'
                }
            });
        }).catch(err => {
            EditorToaster.show({
                message: 'Failed to update. Error was logged to console.',
                intent: Intent.DANGER,
                icon: IconNames.CROSS
            });
            console.error(err);
        })
    }

    onSubmitDraft() {
    }

    render() {
        if (!this.state.post) {
            return 'Loading...';
        }
        console.log(this.state.post);
        return (
            <div className={css(styles.container)}>
                <RequireAuth from={this.props.match.url}/>
                <Toaster position={Position.TOP_RIGHT} ref={this.toaster}>
                    {this.state.toasts.map(toast => <Toast {...toast} />)}
                </Toaster>
                {this.state.redirect ? <Redirect to={this.state.redirect}/> : ''}
                <PostEditor
                    post={this.state.post} error={this.state.error}
                    loading={this.state.loading}
                    onSubmit={this.onSubmit} type={'create'}
                    onSubmitDraft={this.onSubmitDraft}
                />
            </div>
        );
    }
}

const styles = StyleSheet.create({
    container: {
        height: '100vh'
    }
});

export default Editor;
